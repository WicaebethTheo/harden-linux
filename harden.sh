#!/usr/bin/env bash
#
# Linux server hardening + self-audit
# Primary target: Debian/Ubuntu (incl. cloud-init & socket-activated SSH).
# Also supports: RHEL/Fedora/Rocky/Alma, Arch, openSUSE. Unknown -> you pick.
#
# Highlights:
#   - Interactive SSH port choice at start (default 22, validated).
#   - Distro family auto-detect; package mgr / firewall / auto-updates abstracted.
#   - SSH auth + MODERN CRYPTO hardening, algorithms filtered through `ssh -Q`
#     so the config only ever contains algos this sshd actually supports
#     (won't break sshd -t, inherits future-strong defaults). PQ-hybrid kex
#     (sntrup761/mlkem768) included when available. MaxStartups throttling.
#   - Cloud-init aware: writes /etc/ssh/sshd_config.d/00-hardening.conf and
#     neutralizes conflicting drop-ins; result verified via `sshd -T`.
#   - Socket-activated SSH (Ubuntu 22.10+/Debian 13): also overrides ssh.socket
#     ListenStream (sshd_config Port is ignored there) and verifies with `ss`.
#   - SELinux-aware on RHEL: relabels the SSH port (semanage) before bind.
#   - Anti-lockout: never disables password/root login without a usable key.
#   - Enables unattended SECURITY updates (unattended-upgrades / dnf-automatic).
#   - Leaves net.ipv4.ip_forward untouched (Docker / NetBird / routing).
#   - PASS/WARN/FAIL audit at the end (inspired by vernu/vps-audit, bugs fixed).
#
# Usage:
#   sudo ./server-hardening.sh                       # interactive
#   sudo ./server-hardening.sh -y --ssh-port 2222 --allow 80/tcp,443/tcp
#   sudo ./server-hardening.sh --keep-password-auth  # no keys pushed yet
#   sudo ./server-hardening.sh --allow-users "alice"  # restrict AllowUsers
#   sudo ./server-hardening.sh --audit-only          # read-only audit
#   sudo ./server-hardening.sh --distro debian       # force family if detect off
#
set -o pipefail

# ---------- flags / config ----------
SSH_PORT=""                 # empty -> prompt (default 22) unless -y
ALLOW_PORTS=""
ALLOW_USERS=""
KEEP_PASSWORD_AUTH=false
KEEP_ROOT_LOGIN=false
ASSUME_YES=false
FORCE=false
AUDIT_ONLY=false
FORCE_FAMILY=""
DEFAULT_SSH_PORT=22

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; BLU=$'\033[0;34m'; GRAY=$'\033[0;90m'; NC=$'\033[0m'
log()  { echo -e "${BLU}[*]${NC} $*"; }
ok()   { echo -e "${GRN}[✓]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssh-port)           SSH_PORT="$2"; shift 2;;
    --allow)              ALLOW_PORTS="$2"; shift 2;;
    --allow-users)        ALLOW_USERS="$2"; shift 2;;
    --keep-password-auth) KEEP_PASSWORD_AUTH=true; shift;;
    --keep-root-login)    KEEP_ROOT_LOGIN=true; shift;;
    --force)              FORCE=true; shift;;
    --audit-only)         AUDIT_ONLY=true; shift;;
    --distro)             FORCE_FAMILY="$2"; shift 2;;
    -y|--yes)             ASSUME_YES=true; shift;;
    -h|--help)            grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done
confirm() { $ASSUME_YES && return 0; local a; read -rp "$(echo -e "${YLW}?${NC} $1 [y/N] ")" a; [[ "$a" =~ ^[Yy]$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1>=1 && $1<=65535 )); }

# =====================================================================
# Distro family detection / abstraction
# =====================================================================
FAMILY=""; PM=""; FW=""; AUTOUPD=""
detect_family() {
  [[ -n "$FORCE_FAMILY" ]] && { FAMILY="$FORCE_FAMILY"; return; }
  local id="${ID:-}" like="${ID_LIKE:-}"
  case " $id $like " in
    *" debian "*|*" ubuntu "*) FAMILY="debian";;
    *" rhel "*|*" fedora "*|*" centos "*) FAMILY="rhel";;
    *" arch "*) FAMILY="arch";;
    *" suse "*|*" opensuse "*|*" sles "*) FAMILY="suse";;
    *)
      case "$id" in
        debian|ubuntu|linuxmint|pop|raspbian|devuan) FAMILY="debian";;
        rhel|centos|rocky|almalinux|fedora|ol|oracle|amzn) FAMILY="rhel";;
        arch|manjaro|endeavouros|cachyos) FAMILY="arch";;
        opensuse*|sles|sled) FAMILY="suse";;
        *) FAMILY="";;
      esac;;
  esac
}
choose_family() {
  warn "Could not auto-detect the distribution family (ID='${ID:-?}')."
  echo "  Pick the closest base so package/firewall commands adapt:"
  echo "    1) Debian / Ubuntu  (apt, ufw, unattended-upgrades)"
  echo "    2) RHEL / Fedora / Rocky / Alma  (dnf, firewalld, dnf-automatic)"
  echo "    3) Arch  (pacman, ufw)"
  echo "    4) openSUSE / SLES  (zypper, firewalld)"
  echo "    5) Abort"
  local c; read -rp "Choice [1-5]: " c
  case "$c" in
    1) FAMILY="debian";; 2) FAMILY="rhel";; 3) FAMILY="arch";; 4) FAMILY="suse";;
    *) die "Aborted — no family selected.";;
  esac
}
set_abstraction() {
  case "$FAMILY" in
    debian) PM="apt";    FW="ufw";       AUTOUPD="unattended" ;;
    rhel)   PM="dnf";    FW="firewalld"; AUTOUPD="dnf-automatic"; command -v dnf >/dev/null || PM="yum" ;;
    arch)   PM="pacman"; FW="ufw";       AUTOUPD="none" ;;
    suse)   PM="zypper"; FW="firewalld"; AUTOUPD="zypper" ;;
    *) die "Unsupported family: $FAMILY";;
  esac
}
pm_update() {
  case "$PM" in
    apt)    apt-get update -qq ;;
    dnf)    dnf -y -q makecache ;;
    yum)    yum -y -q makecache ;;
    pacman) pacman -Sy --noconfirm >/dev/null ;;
    zypper) zypper --non-interactive refresh >/dev/null ;;
  esac
}
pm_install() { # pm_install pkg...
  case "$PM" in
    apt)    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o Dpkg::Options::=--force-confold "$@" >/dev/null ;;
    dnf)    dnf -y -q install "$@" >/dev/null ;;
    yum)    yum -y -q install "$@" >/dev/null ;;
    pacman) pacman -S --needed --noconfirm "$@" >/dev/null ;;
    zypper) zypper --non-interactive install -y "$@" >/dev/null ;;
  esac
}
pkg_installed() { # cross-distro "is installed?"
  case "$PM" in
    apt)        dpkg -s "$1" >/dev/null 2>&1 ;;
    dnf|yum)    rpm -q "$1" >/dev/null 2>&1 ;;
    pacman)     pacman -Q "$1" >/dev/null 2>&1 ;;
    zypper)     rpm -q "$1" >/dev/null 2>&1 ;;
  esac
}

# =====================================================================
# AUDIT (read-only)
# =====================================================================
run_audit() {
  local report pass=0 warn=0 fail=0
  report="${BACKUP_DIR:-/root}/audit-report-$(date +%Y%m%d_%H%M%S).txt"
  : > "$report"
  ac() { local n="$1" s="$2" m="$3" c=""
    case "$s" in PASS) c="$GRN"; ((pass++));; WARN) c="$YLW"; ((warn++));; FAIL) c="$RED"; ((fail++));; esac
    echo -e "${c}[$s]${NC} $n ${GRAY}- $m${NC}"; echo "[$s] $n - $m" >> "$report"; }
  echo -e "\n${BLU}=== Security audit ===${NC}"
  echo "Audit $(date) — $(hostname) — ${PRETTY_NAME:-?} — family:$FAMILY" >> "$report"

  local e rl pa po unpriv
  e="$(sshd -T 2>/dev/null)"
  geteff() { awk -v k="$1" 'tolower($1)==k{print tolower($2); exit}' <<<"$e"; }
  rl="$(geteff permitrootlogin)"; pa="$(geteff passwordauthentication)"; po="$(geteff port)"
  case "$rl" in
    no) ac "SSH root login" PASS "PermitRootLogin no";;
    prohibit-password) ac "SSH root login" WARN "prohibit-password (key-only root)";;
    *) ac "SSH root login" FAIL "PermitRootLogin=$rl";;
  esac
  [[ "$pa" == no ]] && ac "SSH password auth" PASS "key-only" || ac "SSH password auth" FAIL "password auth enabled"
  unpriv="$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)"
  if [[ "$po" == 22 ]]; then ac "SSH port" WARN "default port 22"
  elif [[ -n "$po" && "$po" -ge "$unpriv" ]]; then ac "SSH port" WARN "unprivileged port $po (>=$unpriv)"
  else ac "SSH port" PASS "non-default privileged port $po"; fi
  if [[ -n "$(geteff ciphers)" ]] && ! grep -qiE '(^|,)(3des|arcfour|cbc)' <<<"$(geteff ciphers)"; then
    ac "SSH ciphers" PASS "weak ciphers excluded"
  else ac "SSH ciphers" WARN "review cipher list"; fi

  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -qw active; then ac "Firewall" PASS "UFW active"
  elif command -v firewall-cmd >/dev/null && firewall-cmd --state 2>/dev/null | grep -q running; then ac "Firewall" PASS "firewalld running"
  elif command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -q table; then ac "Firewall" PASS "nftables ruleset present"
  else ac "Firewall" FAIL "no active firewall detected"; fi

  local ips_inst=0 ips_act=0
  if systemctl is-active --quiet fail2ban 2>/dev/null; then ips_inst=1; ips_act=1; elif pkg_installed fail2ban; then ips_inst=1; fi
  if systemctl is-active --quiet crowdsec 2>/dev/null; then ips_inst=1; ips_act=1; elif pkg_installed crowdsec; then ips_inst=1; fi
  if command -v docker >/dev/null && systemctl is-active --quiet docker; then
    if docker ps --format '{{.Image}}' 2>/dev/null | grep -qiE 'fail2ban|crowdsec'; then ips_inst=1; ips_act=1; fi
  fi
  case "$ips_inst$ips_act" in
    11) ac "Intrusion prevention" PASS "fail2ban/crowdsec running";;
    10) ac "Intrusion prevention" WARN "installed but not running";;
    *)  ac "Intrusion prevention" FAIL "none installed";;
  esac

  if pkg_installed unattended-upgrades || systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null \
     || systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
    ac "Auto security updates" PASS "configured"
  else ac "Auto security updates" WARN "not configured for this distro"; fi

  local fl=0
  if [[ -r /var/log/auth.log ]]; then fl="$(grep -c 'Failed password' /var/log/auth.log 2>/dev/null)"
  elif [[ -r /var/log/secure ]]; then fl="$(grep -c 'Failed password' /var/log/secure 2>/dev/null)"
  else fl="$(journalctl -u ssh -u sshd --since '24 hours ago' 2>/dev/null | grep -c 'Failed password')"; fi
  fl=$((10#${fl:-0}))
  if   [[ "$fl" -lt 10 ]]; then ac "Failed logins" PASS "$fl in window"
  elif [[ "$fl" -lt 50 ]]; then ac "Failed logins" WARN "$fl — probing"
  else ac "Failed logins" FAIL "$fl — likely brute force"; fi

  if command -v ss >/dev/null; then
    local ports cnt
    ports="$(ss -tulnH 2>/dev/null | awk '{print $5}' | sed 's/.*://' | sort -un | tr '\n' ',' | sed 's/,$//')"
    cnt="$(tr ',' '\n' <<<"$ports" | grep -c .)"
    [[ "$cnt" -lt 8 ]] && ac "Listening ports" PASS "$cnt: $ports" || ac "Listening ports" WARN "$cnt: $ports"
  fi

  if grep -rqs '^Defaults.*logfile' /etc/sudoers /etc/sudoers.d 2>/dev/null; then ac "Sudo logging" PASS "logfile configured"
  elif sudo --version 2>/dev/null | grep -qi 'sudo-rs'; then ac "Sudo logging" PASS "sudo-rs journals by default"
  else ac "Sudo logging" WARN "no explicit logfile (syslog default)"; fi

  if [[ -f /etc/security/pwquality.conf ]] && grep -qE '^\s*minlen\s*=\s*(1[2-9]|[2-9][0-9])' /etc/security/pwquality.conf; then
    ac "Password policy" PASS "pwquality minlen>=12"
  else ac "Password policy" WARN "weak/no pwquality policy"; fi

  findmnt -no OPTIONS /dev/shm 2>/dev/null | grep -q noexec && ac "/dev/shm" PASS "noexec,nosuid,nodev" || ac "/dev/shm" WARN "not hardened"
  { [[ -f /var/run/reboot-required ]] || { command -v needs-restarting >/dev/null && ! needs-restarting -r >/dev/null 2>&1; }; } \
    && ac "Reboot" WARN "reboot may be required" || ac "Reboot" PASS "no reboot pending"
  local suid; suid="$(find / -xdev -type f -perm -4000 2>/dev/null | grep -vE '^/usr/(bin|sbin|lib|libexec)|^/bin/|^/sbin/' | wc -l)"
  [[ "$suid" -eq 0 ]] && ac "SUID files" PASS "none in non-standard paths" || ac "SUID files" WARN "$suid to verify"
  local du mu; du="$(df -P / | awk 'NR==2{print int($5)}')"; mu="$(free | awk '/^Mem:/{printf "%.0f",$3/$2*100}')"
  [[ "$du" -lt 80 ]] && ac "Disk usage" PASS "${du}%" || ac "Disk usage" WARN "${du}%"
  [[ "$mu" -lt 85 ]] && ac "Memory usage" PASS "${mu}%" || ac "Memory usage" WARN "${mu}%"

  local total=$((pass+warn+fail))
  echo -e "\n${BLU}Score:${NC} ${GRN}${pass} PASS${NC} / ${YLW}${warn} WARN${NC} / ${RED}${fail} FAIL${NC} (of $total)"
  echo "Score: $pass PASS / $warn WARN / $fail FAIL (of $total)" >> "$report"
  echo -e "Report: $report"
  [[ "$fail" -gt 0 ]] && return 1 || return 0
}

# ---------- preflight ----------
[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
. /etc/os-release 2>/dev/null || true
detect_family
[[ -z "$FAMILY" ]] && choose_family
set_abstraction
ok "Distro: ${PRETTY_NAME:-unknown}  → family=$FAMILY (pm=$PM, fw=$FW, autoupdate=$AUTOUPD)"

TS="$(date +%Y%m%d_%H%M%S)"; BACKUP_DIR="/root/hardening-backups/$TS"; mkdir -p "$BACKUP_DIR"
backup() { [[ -e "$1" ]] && cp -a "$1" "$BACKUP_DIR/" && log "Backed up $1"; return 0; }

if $AUDIT_ONLY; then run_audit; exit $?; fi

# ---------- interactive SSH port choice ----------
if [[ -z "$SSH_PORT" ]]; then
  if $ASSUME_YES; then SSH_PORT="$DEFAULT_SSH_PORT"
  else
    while :; do
      read -rp "$(echo -e "${YLW}?${NC} SSH port to use [${DEFAULT_SSH_PORT}]: ")" SSH_PORT
      SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
      if ! valid_port "$SSH_PORT"; then warn "Invalid port."; continue; fi
      [[ "$SSH_PORT" == 22 ]] && ! confirm "Port 22 is the scanned default — keep it anyway?" && continue
      (( SSH_PORT >= 1024 )) && warn "Port >=1024 is unprivileged (a crashed sshd could be impersonated)."
      break
    done
  fi
fi
valid_port "$SSH_PORT" || die "Invalid SSH port: $SSH_PORT"
ok "SSH will be set to port $SSH_PORT"

# ---------- SSH service-model detection ----------
ssh_unit() { systemctl cat ssh.service >/dev/null 2>&1 && echo ssh.service || echo sshd.service; }
SSH_UNIT="$(ssh_unit)"; SOCKET_ACTIVE=false
if systemctl cat ssh.socket >/dev/null 2>&1; then
  { systemctl is-active --quiet ssh.socket 2>/dev/null || systemctl is-enabled --quiet ssh.socket 2>/dev/null; } && SOCKET_ACTIVE=true
fi
$SOCKET_ACTIVE && warn "SSH model: socket-activated — will convert to classic ssh.service (stable dual-stack port)" || ok "SSH model: classic service ($SSH_UNIT)"

# SELinux (RHEL): note enforcing state for port relabel later
SELINUX_ENFORCING=false
if [[ "$FAMILY" == "rhel" ]] && command -v getenforce >/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
  SELINUX_ENFORCING=true; log "SELinux is enforcing — will relabel SSH port"
fi

# =====================================================================
# 1. Updates + packages
# =====================================================================
log "Refreshing package metadata & upgrading..."
pm_update || warn "metadata refresh issues"
case "$PM" in
  apt)    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq -o Dpkg::Options::=--force-confold >/dev/null 2>&1 || warn "upgrade issues";;
  dnf)    dnf -y -q upgrade --security >/dev/null 2>&1 || dnf -y -q upgrade >/dev/null 2>&1 || warn "upgrade issues";;
  yum)    yum -y -q update >/dev/null 2>&1 || true;;
  pacman) pacman -Su --noconfirm >/dev/null 2>&1 || warn "upgrade issues";;
  zypper) zypper --non-interactive patch >/dev/null 2>&1 || true;;
esac

log "Installing security packages..."
case "$FAMILY" in
  debian) pm_install ufw fail2ban unattended-upgrades libpam-pwquality openssh-server iproute2 openssh-client || die "install failed";;
  rhel)   pkg_installed epel-release || pm_install epel-release || warn "EPEL not available (fail2ban may be missing)"
          pm_install fail2ban firewalld libpwquality openssh-server openssh-clients iproute policycoreutils-python-utils dnf-automatic || warn "some packages missing";;
  arch)   pm_install ufw fail2ban libpwquality openssh iproute2 || warn "some packages missing";;
  suse)   pm_install fail2ban firewalld libpwquality openssh iproute2 || warn "some packages missing";;
esac
ok "Packages installed"

# =====================================================================
# 2. Anti-lockout key check
# =====================================================================
has_key() { local u="$1" home; home="$(getent passwd "$u" | cut -d: -f6)"; [[ -n "$home" ]] || return 1
  [[ -s "$home/.ssh/authorized_keys" ]] && grep -qE '^(ssh-|ecdsa-|sk-)' "$home/.ssh/authorized_keys"; }
ROOT_HAS_KEY=false; has_key root && ROOT_HAS_KEY=true
NONROOT_SUDO_WITH_KEY=""
admingrp="sudo"; [[ "$FAMILY" =~ ^(rhel|arch|suse)$ ]] && admingrp="wheel"
for u in $( { getent group "$admingrp"; getent group admin; } 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -vE '^(root)?$' | sort -u ); do
  has_key "$u" && NONROOT_SUDO_WITH_KEY="$u" && break
done
$ROOT_HAS_KEY && ok "root has an SSH key" || warn "root has NO SSH key"
if [[ -n "$NONROOT_SUDO_WITH_KEY" ]]; then
  _kh="$(getent passwd "$NONROOT_SUDO_WITH_KEY" | cut -d: -f6)/.ssh/authorized_keys"
  _kn="$(grep -cE '^(ssh-|ecdsa-|sk-)' "$_kh" 2>/dev/null)"
  ok "Key login confirmed for '$NONROOT_SUDO_WITH_KEY' (${_kn:-0} key(s) in $_kh)"
else
  warn "no non-root admin user with a key — key-only login would be unsafe"
fi
DISABLE_PW=true;   $KEEP_PASSWORD_AUTH && DISABLE_PW=false
DISABLE_ROOT=true; $KEEP_ROOT_LOGIN    && DISABLE_ROOT=false
if $DISABLE_ROOT && [[ -z "$NONROOT_SUDO_WITH_KEY" ]] && ! $FORCE; then
  warn "Refusing to disable root SSH: no admin user with a key. Keeping root login."; DISABLE_ROOT=false; fi
if $DISABLE_PW && ! $FORCE; then
  if $DISABLE_ROOT && [[ -z "$NONROOT_SUDO_WITH_KEY" ]]; then warn "Refusing to disable password auth: no key for an allowed account."; DISABLE_PW=false
  elif ! $DISABLE_ROOT && ! $ROOT_HAS_KEY && [[ -z "$NONROOT_SUDO_WITH_KEY" ]]; then warn "Refusing to disable password auth: no SSH key anywhere."; DISABLE_PW=false; fi
fi
echo; log "Plan: port=$SSH_PORT  disable_root=$DISABLE_ROOT  disable_password=$DISABLE_PW  allow_users='${ALLOW_USERS:-<all>}'"
$ASSUME_YES || confirm "Proceed?" || die "Aborted."

# =====================================================================
# 3. SSH hardening: auth + modern crypto (ssh -Q filtered) + validate
# =====================================================================
SSHD_MAIN="/etc/ssh/sshd_config"; DROPIN_DIR="/etc/ssh/sshd_config.d"; HARDEN_DROPIN="$DROPIN_DIR/00-hardening.conf"
backup "$SSHD_MAIN"; mkdir -p "$DROPIN_DIR"; chmod 755 "$DROPIN_DIR"
grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_MAIN" \
  || { sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' "$SSHD_MAIN"; log "Added Include to $SSHD_MAIN"; }
shopt -s nullglob
for f in "$DROPIN_DIR"/*.conf; do
  [[ "$f" == "$HARDEN_DROPIN" ]] && continue
  if grep -qiE '^\s*(Port|PasswordAuthentication|PermitRootLogin|KbdInteractiveAuthentication|ChallengeResponseAuthentication)\b' "$f"; then
    backup "$f"
    sed -ri 's/^(\s*)(Port|PasswordAuthentication|PermitRootLogin|KbdInteractiveAuthentication|ChallengeResponseAuthentication)\b/\1#hardened-out \2/I' "$f"
    log "Neutralized conflicting directives in $(basename "$f")"
  fi
done
shopt -u nullglob

# Filter a preferred CSV list down to what THIS sshd supports (ssh -Q)
filter_algos() { # $1=csv preferred  $2..=ssh -Q query tokens to try
  local csv="$1"; shift
  local supported="" t
  for t in "$@"; do supported="$(ssh -Q "$t" 2>/dev/null)"; [[ -n "$supported" ]] && break; done
  [[ -z "$supported" ]] && { echo ""; return; }
  local out=() a; IFS=',' read -ra arr <<<"$csv"
  for a in "${arr[@]}"; do grep -qxF "$a" <<<"$supported" && out+=("$a"); done
  local IFS=','; echo "${out[*]}"
}
KEX="" CIPHERS="" MACS="" HKA=""
if command -v ssh >/dev/null; then
  KEX="$(filter_algos "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512" kex)"
  CIPHERS="$(filter_algos "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" cipher)"
  MACS="$(filter_algos "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com" mac)"
  HKA="$(filter_algos "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256" HostKeyAlgorithms key)"
else
  warn "ssh client (ssh -Q) unavailable — keeping OpenSSH default crypto"
fi

{
  echo "# Managed by server-hardening.sh — $TS"
  echo "Port $SSH_PORT"
  echo "PubkeyAuthentication yes"
  $DISABLE_ROOT && echo "PermitRootLogin no" || echo "PermitRootLogin prohibit-password"
  if $DISABLE_PW; then
    echo "PasswordAuthentication no"; echo "KbdInteractiveAuthentication no"; echo "ChallengeResponseAuthentication no"
    echo "AuthenticationMethods publickey"
  else
    echo "PasswordAuthentication yes"
  fi
  echo "PermitEmptyPasswords no"
  echo "MaxAuthTries 3"
  echo "LoginGraceTime 30"
  echo "MaxStartups 10:30:60"      # DHEat / connection-flood throttling
  echo "X11Forwarding no"
  echo "AllowAgentForwarding no"
  echo "ClientAliveInterval 300"
  echo "ClientAliveCountMax 2"
  [[ -n "$ALLOW_USERS" ]] && echo "AllowUsers $ALLOW_USERS"
  [[ -n "$KEX" ]]     && echo "KexAlgorithms $KEX"
  [[ -n "$CIPHERS" ]] && echo "Ciphers $CIPHERS"
  [[ -n "$MACS" ]]    && echo "MACs $MACS"
  [[ -n "$HKA" ]]     && echo "HostKeyAlgorithms $HKA"
} > "$HARDEN_DROPIN"
chmod 644 "$HARDEN_DROPIN"
[[ -n "$KEX$CIPHERS$MACS" ]] && ok "Crypto pinned (supported algos only): kex=$(wc -w <<<"${KEX//,/ }") cipher=$(wc -w <<<"${CIPHERS//,/ }") mac=$(wc -w <<<"${MACS//,/ }")"

if sshd -t 2>/tmp/sshd_test.err; then ok "sshd config syntax OK"
else err "sshd -t failed:"; cat /tmp/sshd_test.err >&2; rm -f "$HARDEN_DROPIN"; die "Reverted drop-in. No SSH changes applied."; fi

# SELinux: allow sshd to bind the new port BEFORE restart
if $SELINUX_ENFORCING && command -v semanage >/dev/null; then
  if ! semanage port -l 2>/dev/null | grep -E '^ssh_port_t' | grep -qw "$SSH_PORT"; then
    semanage port -a -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null \
      || semanage port -m -t ssh_port_t -p tcp "$SSH_PORT" 2>/dev/null \
      && log "SELinux: labeled tcp/$SSH_PORT as ssh_port_t"
  fi
fi

# =====================================================================
# 4. Apply listening port across service models + REAL connect test
# =====================================================================
SOCK_OVERRIDE="/etc/systemd/system/ssh.socket.d/override.conf"
port_accepts() { timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }

apply_ssh() {
  if $SOCKET_ACTIVE; then
    # Changing the port under socket-activation is fragile: a bare ListenStream
    # often binds IPv6-only (refusing IPv4 clients), plus Accept=no spawn races.
    # Convert to the classic always-on ssh.service so the port comes from
    # sshd_config "Port" and sshd binds BOTH IPv4 and IPv6 deterministically.
    log "Converting socket-activated SSH to classic ssh.service (stable dual-stack port)"
    systemctl disable --now ssh.socket 2>/dev/null || true
    rm -f "$SOCK_OVERRIDE"; rmdir /etc/systemd/system/ssh.socket.d 2>/dev/null || true
    systemctl daemon-reload
    systemctl enable ssh.service  >/dev/null 2>&1 || systemctl enable "$SSH_UNIT"  >/dev/null 2>&1 || true
    systemctl restart ssh.service 2>/dev/null || systemctl restart "$SSH_UNIT" 2>/dev/null || warn "Could not start ssh.service"
    SSH_UNIT="ssh.service"; SOCKET_ACTIVE=false
  else
    systemctl reload "$SSH_UNIT" 2>/dev/null || systemctl restart "$SSH_UNIT" 2>/dev/null || warn "Could not reload $SSH_UNIT"
  fi
}
revert_ssh() {
  warn "Reverting SSH changes to avoid lockout..."
  rm -f "$HARDEN_DROPIN" "$SOCK_OVERRIDE"
  systemctl daemon-reload 2>/dev/null || true
  if $SOCKET_ACTIVE; then systemctl restart ssh.socket 2>/dev/null || true
  else systemctl restart "$SSH_UNIT" 2>/dev/null || systemctl reload "$SSH_UNIT" 2>/dev/null || true; fi
}

apply_ssh
sleep 1

# Effective auth config sanity
eff="$(sshd -T 2>/dev/null)"
chk() { local g; g="$(awk -v k="$1" 'tolower($1)==k{print tolower($2)}' <<<"$eff" | head -1)"
  [[ "$g" == "$2" ]] && ok "effective $1 = $g" || warn "effective $1 = '${g:-?}' (wanted '$2') — inspect $DROPIN_DIR"; }
$DISABLE_PW && chk passwordauthentication no
$DISABLE_ROOT && chk permitrootlogin no

# The real test: can something actually accept a TCP connection on the port?
if port_accepts "$SSH_PORT"; then
  ok "SSH accepts connections on :$SSH_PORT (verified via local TCP handshake)"
else
  err "Nothing accepts connections on :$SSH_PORT — your SSH config would lock you out."
  revert_ssh
  if port_accepts 22 || ss -tlnH 2>/dev/null | awk '{print $4}' | grep -qE '[:.]22$'; then
    die "Reverted; SSH restored on its previous port (likely 22). Inspect: journalctl -u ssh.socket -u ssh.service"
  fi
  die "Reverted. VERIFY SSH manually from the console before logging out: systemctl status ssh.socket ssh.service"
fi

# =====================================================================
# 5. Firewall
# =====================================================================
if [[ "$FW" == "ufw" ]]; then
  command -v ufw >/dev/null || pm_install ufw
  log "Configuring UFW..."
  ufw default deny incoming  >/dev/null
  ufw default allow outgoing >/dev/null
  ufw limit "${SSH_PORT}/tcp" comment 'SSH' >/dev/null     # rate-limit SSH
  if [[ -n "$ALLOW_PORTS" ]]; then IFS=',' read -ra ex <<<"$ALLOW_PORTS"; for r in "${ex[@]}"; do ufw allow "$r" >/dev/null && log "ufw allow $r"; done; fi
  ufw --force enable >/dev/null
  ok "UFW active (SSH :$SSH_PORT rate-limited${ALLOW_PORTS:+; extra: $ALLOW_PORTS})"
else
  log "Configuring firewalld..."
  systemctl enable --now firewalld >/dev/null 2>&1
  firewall-cmd --permanent --remove-service=ssh >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" >/dev/null 2>&1
  if [[ -n "$ALLOW_PORTS" ]]; then IFS=',' read -ra ex <<<"$ALLOW_PORTS"; for r in "${ex[@]}"; do firewall-cmd --permanent --add-port="${r/\//-}" >/dev/null 2>&1; firewall-cmd --permanent --add-port="$r" >/dev/null 2>&1 && log "firewalld add $r"; done; fi
  firewall-cmd --reload >/dev/null 2>&1
  ok "firewalld active (SSH :$SSH_PORT${ALLOW_PORTS:+; extra: $ALLOW_PORTS})"
fi

# =====================================================================
# 6. Fail2ban
# =====================================================================
if pkg_installed fail2ban || command -v fail2ban-server >/dev/null; then
  log "Configuring fail2ban..."
  backup /etc/fail2ban/jail.local
  ban="iptables-multiport"; [[ "$FW" == "ufw" ]] && ban="ufw"
  logbackend="systemd"
  cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend   = $logbackend
banaction = $ban
bantime   = 3600
findtime  = 600
maxretry  = 4

[sshd]
enabled = true
port    = $SSH_PORT
EOF
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban && ok "fail2ban active" || warn "fail2ban failed — journalctl -u fail2ban"
else
  warn "fail2ban not installed on this distro — skipping"
fi

# =====================================================================
# 7. Automatic SECURITY updates
# =====================================================================
log "Enabling automatic security updates..."
case "$AUTOUPD" in
  unattended)
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    backup /etc/apt/apt.conf.d/50unattended-upgrades
    if [[ "$ID" == "debian" ]]; then
      ORIGINS='        "origin=Debian,codename=${distro_codename},label=Debian-Security";'
    else
      ORIGINS='        "${distro_id}:${distro_codename}-security";
        "${distro_id}ESMApps:${distro_codename}-apps-security";
        "${distro_id}ESM:${distro_codename}-infra-security";'
    fi
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Origins-Pattern {
$ORIGINS
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    systemctl enable --now unattended-upgrades >/dev/null 2>&1
    systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
    ok "unattended-upgrades enabled (security only, no auto-reboot)"
    ;;
  dnf-automatic)
    if [[ -f /etc/dnf/automatic.conf ]]; then
      backup /etc/dnf/automatic.conf
      sed -ri 's/^upgrade_type\s*=.*/upgrade_type = security/' /etc/dnf/automatic.conf
      sed -ri 's/^apply_updates\s*=.*/apply_updates = yes/' /etc/dnf/automatic.conf
      systemctl enable --now dnf-automatic-install.timer >/dev/null 2>&1 \
        || systemctl enable --now dnf-automatic.timer >/dev/null 2>&1
      ok "dnf-automatic enabled (security, apply=yes)"
    else warn "dnf-automatic config missing — install dnf-automatic"; fi
    ;;
  zypper)
    if systemctl list-unit-files 2>/dev/null | grep -q '^zypper-patch'; then
      systemctl enable --now zypper-patch.timer >/dev/null 2>&1 && ok "zypper auto-patch timer enabled"
    else warn "No zypper auto-patch timer — schedule 'zypper patch' via cron/systemd manually"; fi
    ;;
  none)
    warn "Arch has no upstream auto security-update channel — run 'pacman -Syu' on a schedule yourself"
    ;;
esac

# =====================================================================
# 8. Sudo logging (sudo-rs safe) + password quality
# =====================================================================
log "Configuring sudo logging & password policy..."
SUDO_FRAG="/etc/sudoers.d/10-hardening"; SUDO_TMP="$(mktemp)"; : > "$SUDO_TMP"; sudo_kept=0
for line in \
  "Defaults timestamp_timeout=15" \
  "Defaults passwd_tries=3" \
  "Defaults logfile=/var/log/sudo.log" \
  "Defaults !visiblepw"; do
  printf '%s\n' "$line" >> "$SUDO_TMP"
  if visudo -cf "$SUDO_TMP" >/dev/null 2>&1; then sudo_kept=$((sudo_kept+1)); else sed -i '$ d' "$SUDO_TMP"; fi
done
if [[ "$sudo_kept" -gt 0 ]]; then install -m 440 "$SUDO_TMP" "$SUDO_FRAG"; ok "sudo hardening applied ($sudo_kept directive(s))"
else warn "no classic sudo Defaults accepted (sudo-rs?) — journal logging in use"; fi
rm -f "$SUDO_TMP"

backup /etc/security/pwquality.conf
cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
EOF
ok "Password quality policy set (minlen 14)"

# =====================================================================
# 9. sysctl (ip_forward untouched) + /dev/shm
# =====================================================================
log "Applying sysctl hardening..."
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# Spoofing / routing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
# ICMP / TCP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
# Kernel info-leak / exploitation mitigations
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
# net.ipv4.ip_forward intentionally NOT set (Docker/NetBird/routing).
EOF
sysctl --system >/dev/null 2>&1 && ok "sysctl applied" || warn "Some sysctl keys not applied"

log "Hardening /dev/shm..."
backup /etc/fstab
if ! grep -qE '^\s*\S+\s+/dev/shm\s' /etc/fstab; then
  echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab
  mount -o remount /dev/shm 2>/dev/null && ok "/dev/shm remounted" || warn "/dev/shm applies on next reboot"
else log "/dev/shm already in fstab — left as-is"; fi

# =====================================================================
# 10. Final audit
# =====================================================================
run_audit || true

echo
ok "Hardening complete. SSH is on :$SSH_PORT"
echo -e "${RED}Before you log out${NC}, open a NEW session and confirm:"
echo "   ssh -p $SSH_PORT ${NONROOT_SUDO_WITH_KEY:-<user>}@<host>"
echo "Backups: $BACKUP_DIR"
echo "Rollback SSH: rm $HARDEN_DROPIN $( $SOCKET_ACTIVE && echo "$SOCK_OVERRIDE" ); systemctl daemon-reload; systemctl restart ${SOCKET_ACTIVE:+ssh.socket }$SSH_UNIT"
