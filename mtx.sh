#!/usr/bin/env bash
# mtx.sh — Reliable MTProto Proxy installer (C with auto-fallback to Python)
# OS: Ubuntu/Debian (22.04/24.04+), systemd required

set -euo pipefail
VERSION="1.0.0"

# Defaults
IMPL="auto"        # auto | c | python
PORT=8443
SECRET=""
TLS_HOST="www.microsoft.com"
AD_TAG=""
WORKERS=""
AUTOSTART=1

# Paths
C_SRC_DIR="/opt/MTProxy"
C_BIN="$C_SRC_DIR/objs/bin/mtproto-proxy"
C_WD="$C_SRC_DIR/objs/bin"
P_DIR="/opt/mtprotoproxy"
P_VENV="/opt/mtprotoproxy-venv"
CONF_DIR="/etc/mtproxy"
LOG_DIR="/var/log/mtproxy"
USER_NAME="mtproxy"
BUILD_LOG="/tmp/mtx_build.log"

# Helpers
msg(){ echo -e "\033[1;36m[mtx]\033[0m $*"; }
err(){ echo -e "\033[1;31m[mtx]\033[0m $*"; } >&2
need_root(){ [ "${EUID:-$(id -u)}" -eq 0 ] || { err "Run with sudo/root."; exit 1; }; }
has(){ command -v "$1" >/dev/null 2>&1; }
pubip(){ curl -fsS4 https://api.ipify.org || curl -fsS4 https://ifconfig.me || hostname -I | awk '{print $1}'; }
rand_secret(){ head -c 16 /dev/urandom | xxd -ps; }
hex(){ printf '%s' "$1" | xxd -ps -c 200 | tr -d '\n'; }
cpus(){ nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2; }

open_fw(){
  local p="$1"
  if has ufw; then ufw allow "$p"/tcp || true
  elif has firewall-cmd; then firewall-cmd --permanent --add-port="${p}/tcp" || true; firewall-cmd --reload || true
  else msg "No ufw/firewalld detected; ensure TCP ${p} is reachable."; fi
}

mk_user_dirs(){
  id -u "$USER_NAME" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$USER_NAME"
  mkdir -p "$CONF_DIR" "$LOG_DIR"
  chown -R "$USER_NAME:$USER_NAME" "$LOG_DIR" || true
}

write_env(){
  mkdir -p "$CONF_DIR"
  cat >"$CONF_DIR/mtproxy.env" <<EOF
PORT="${PORT}"
SECRET="${SECRET}"
TLS_HOST="${TLS_HOST}"
AD_TAG="${AD_TAG}"
WORKERS="${WORKERS}"
EOF
}

deps_common(){
  msg "Installing common deps..."
  if has apt-get; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y git curl ca-certificates xxd build-essential pkg-config
  elif has yum; then
    yum install -y git curl ca-certificates xxd gcc make pkgconfig
  else
    err "Unsupported package manager"; exit 1
  fi
}
deps_c(){
  msg "Installing C build deps..."
  if has apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl-dev zlib1g-dev
  else
    yum install -y openssl-devel zlib-devel || true
  fi
}
deps_python(){
  msg "Installing Python deps..."
  if has apt-get; then
    apt-get install -y python3 python3-venv python3-pip libffi-dev libssl-dev
  else
    err "Python path supports apt-based distros only for now"; exit 1
  fi
}

patch_makefile_for_c(){
  # Apply robust flags into Makefile so all compile/link steps get them.
  local mf="$C_SRC_DIR/Makefile"
  local GCC_MAJ; GCC_MAJ=$(gcc -dumpfullversion -dumpversion 2>/dev/null | cut -d. -f1 || echo 0)
  local ARCH; ARCH="$(uname -m)"
  local X86_FLAGS=""
  if [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
    # Add CX16 only if CPU supports it
    if grep -qm1 -E '\bcx16\b' /proc/cpuinfo 2>/dev/null; then
      X86_FLAGS="-msse2 -msse4.2 -mpclmul -mcx16"
    else
      X86_FLAGS="-msse2 -msse4.2 -mpclmul"
    fi
  fi
  local OSSLCFLAGS; OSSLCFLAGS="$(pkg-config --cflags openssl 2>/dev/null || true)"
  local OSSLIBS;    OSSLIBS="$(pkg-config --libs   openssl 2>/dev/null || echo '-lssl -lcrypto')"

  sed -i "1i \
CFLAGS += -D_GNU_SOURCE -D_DEFAULT_SOURCE ${OSSLCFLAGS} ${X86_FLAGS} $([ \"$GCC_MAJ\" -ge 10 ] && echo -fcommon)\n\
LDFLAGS += ${OSSLIBS} -lm -latomic\n" "$mf"
}

build_c(){
  : > "$BUILD_LOG"
  msg "Cloning & building MTProxy (C)..."
  rm -rf "$C_SRC_DIR"
  git clone https://github.com/TelegramMessenger/MTProxy "$C_SRC_DIR" >>"$BUILD_LOG" 2>&1
  patch_makefile_for_c
  ( cd "$C_SRC_DIR" && make clean >>"$BUILD_LOG" 2>&1 && make >>"$BUILD_LOG" 2>&1 ) || return 1
  return 0
}

install_c(){
  deps_common; deps_c; mk_user_dirs
  if [ ! -x "$C_BIN" ]; then
    if ! build_c; then
      err "C build failed. See $BUILD_LOG"
      return 1
    fi
  else
    msg "C binary exists; skipping rebuild."
  fi

  mkdir -p "$C_WD"
  curl -fsSL https://core.telegram.org/getProxySecret -o "$C_WD/proxy-secret"
  curl -fsSL https://core.telegram.org/getProxyConfig -o "$C_WD/proxy-multi.conf"
  chown -R "$USER_NAME:$USER_NAME" "$C_SRC_DIR"

  [ -z "$SECRET" ] && SECRET="$(rand_secret)"
  [ -z "$WORKERS" ] && WORKERS=$(( $(cpus) - 1 )); [ "$WORKERS" -lt 1 ] && WORKERS=1
  write_env

  cat >/opt/MTProxy/run.sh <<'RUN'
#!/usr/bin/env bash
set -euo pipefail
. /etc/mtproxy/mtproxy.env
cd /opt/MTProxy/objs/bin
ARGS=(-u mtproxy -p 8888 -H "${PORT}" -S "${SECRET}" --aes-pwd /opt/MTProxy/objs/bin/proxy-secret /opt/MTProxy/objs/bin/proxy-multi.conf -M "${WORKERS}")
if [ -n "${AD_TAG:-}" ]; then ARGS+=(-P "${AD_TAG}"); fi
exec /opt/MTProxy/objs/bin/mtproto-proxy "${ARGS[@]}"
RUN
  chmod +x /opt/MTProxy/run.sh
  chown "$USER_NAME:$USER_NAME" /opt/MTProxy/run.sh

  cat >/etc/systemd/system/MTProxy.service <<'UNIT'
[Unit]
Description=Telegram MTProto Proxy (Official C)
After=network.target
[Service]
Type=simple
EnvironmentFile=/etc/mtproxy/mtproxy.env
ExecStart=/opt/MTProxy/run.sh
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=infinity
User=mtproxy
Group=mtproxy
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  open_fw "$PORT"

  cat >/opt/MTProxy/update.sh <<'UPD'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/MTProxy/objs/bin
curl -fsSL https://core.telegram.org/getProxySecret -o proxy-secret.new
curl -fsSL https://core.telegram.org/getProxyConfig -o proxy-multi.conf.new
mv -f proxy-secret.new proxy-secret
mv -f proxy-multi.conf.new proxy-multi.conf
systemctl reload MTProxy.service 2>/dev/null || systemctl restart MTProxy.service
UPD
  chmod +x /opt/MTProxy/update.sh
  chown -R "$USER_NAME:$USER_NAME" /opt/MTProxy

  cat >/etc/systemd/system/mtproxy-update.service <<'SVC'
[Unit]
Description=Update Telegram MTProxy config/secret
After=network.target
[Service]
Type=oneshot
ExecStart=/opt/MTProxy/update.sh
SVC
  cat >/etc/systemd/system/mtproxy-update.timer <<'TMR'
[Unit]
Description=Daily MTProxy config updater
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
TMR

  systemctl daemon-reload
  if [ "$AUTOSTART" -eq 1 ]; then
    systemctl enable --now MTProxy.service
    systemctl enable --now mtproxy-update.timer
  else
    systemctl enable mtproxy-update.timer
  fi
}

install_python(){
  deps_common; deps_python; mk_user_dirs
  [ -d "$P_DIR" ] || git clone -b stable https://github.com/alexbers/mtprotoproxy "$P_DIR"
  python3 -m venv "$P_VENV"
  "$P_VENV/bin/pip" install --upgrade pip || true
  "$P_VENV/bin/pip" install cryptography uvloop || true  # optional accel
  [ -z "$SECRET" ] && SECRET="$(rand_secret)"
  cat >"$P_DIR/config.py" <<PY
PORT = ${PORT}
USERS = { 1: '${SECRET}' }
AD_TAG = '${AD_TAG}'
FAKE_TLS_DOMAIN = '${TLS_HOST}'
PY
  chown -R "$USER_NAME:$USER_NAME" "$P_DIR"
  write_env
  cat >/etc/systemd/system/mtprotoproxy.service <<'UNIT'
[Unit]
Description=Async MTProto proxy for Telegram (Python)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
EnvironmentFile=/etc/mtproxy/mtproxy.env
WorkingDirectory=/opt/mtprotoproxy
ExecStart=/opt/mtprotoproxy-venv/bin/python /opt/mtprotoproxy/mtprotoproxy.py
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=infinity
User=mtproxy
Group=mtproxy
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  open_fw "$PORT"
  if [ "$AUTOSTART" -eq 1 ]; then systemctl enable --now mtprotoproxy.service; fi
}

print_links(){
  local ip; ip="$(pubip)"
  local ee="ee${SECRET}$(hex "$TLS_HOST")"
  echo -e "\nShare these (replace server with your domain if any):\n"
  echo "tg://proxy?server=${ip}&port=${PORT}&secret=${SECRET}"
  echo "tg://proxy?server=${ip}&port=${PORT}&secret=dd${SECRET}"
  echo "tg://proxy?server=${ip}&port=${PORT}&secret=${ee}   # FakeTLS"
  echo
  echo "https://t.me/proxy?server=${ip}&port=${PORT}&secret=${SECRET}"
  echo "https://t.me/proxy?server=${ip}&port=${PORT}&secret=dd${SECRET}"
  echo "https://t.me/proxy?server=${ip}&port=${PORT}&secret=${ee}"
}

usage(){
  cat <<USAGE
mtx-autoproxy v${VERSION}
Usage: sudo bash mtx-autoproxy.sh <install|uninstall|status|logs|print-links|rotate-secret|health>
Options for install:
  --impl auto|c|python   (default: auto)
  --port N               (default: 443)
  --secret HEX32         (auto if omitted)
  --tls HOST             (default: www.microsoft.com)
  --ad-tag HEX32
  --workers N            (C impl; default: CPU-1)
  --no-autostart
USAGE
}

parse(){
  local action=""; [ $# -gt 0 ] || { usage; exit 1; }
  action="$1"; shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --impl) IMPL="$2"; shift 2;;
      --port|-p) PORT="$2"; shift 2;;
      --secret|-s) SECRET="$2"; shift 2;;
      --tls|--mask-host) TLS_HOST="$2"; shift 2;;
      --ad-tag|-t) AD_TAG="$2"; shift 2;;
      --workers) WORKERS="$2"; shift 2;;
      --no-autostart) AUTOSTART=0; shift;;
      -h|--help) usage; exit 0;;
      *) break;;
    esac
  done
  echo "$action"
}

rotate_secret(){
  local new; new="$(rand_secret)"; SECRET="$new"; write_env
  if systemctl list-units --type=service | grep -q '^MTProxy'; then systemctl restart MTProxy.service; fi
  if systemctl list-units --type=service | grep -q '^mtprotoproxy'; then systemctl restart mtprotoproxy.service; fi
  msg "Rotated secret -> $new"; print_links
}

health(){
  ss -ltnp | grep -q ":${PORT} " && msg "Port ${PORT} is LISTENING." || err "Port ${PORT} is NOT listening."
  systemctl status MTProxy.service 2>/dev/null || true
  systemctl status mtprotoproxy.service 2>/dev/null || true
}

uninstall_all(){
  systemctl disable --now MTProxy.service 2>/dev/null || true
  systemctl disable --now mtprotoproxy.service 2>/dev/null || true
  systemctl disable --now mtproxy-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/MTProxy.service /etc/systemd/system/mtprotoproxy.service /etc/systemd/system/mtproxy-update.service /etc/systemd/system/mtproxy-update.timer
  systemctl daemon-reload
  rm -rf "$C_SRC_DIR" "$P_DIR" "$P_VENV" "$CONF_DIR" "$LOG_DIR" /opt/MTProxy
  id -u "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" 2>/dev/null || true
  msg "Uninstalled."
}

status_s(){ systemctl status MTProxy.service 2>/dev/null || true; systemctl status mtprotoproxy.service 2>/dev/null || true; }
logs_s(){ journalctl -u MTProxy.service -n 100 --no-pager 2>/dev/null || true; journalctl -u mtprotoproxy.service -n 100 --no-pager 2>/dev/null || true; }

main(){
  need_root
  local act; act="$(parse "$@")"
  [ -z "$SECRET" ] && SECRET="$(rand_secret)"
  case "$act" in
    install)
      case "$IMPL" in
        auto)
          if install_c; then
            msg "C MTProxy installed."
          else
            msg "Falling back to Python (C build failed)."
            install_python
          fi;;
        c) install_c ;;
        python) install_python ;;
        *) err "--impl must be auto|c|python"; exit 1 ;;
      esac
      msg "Install complete."; print_links ;;
    uninstall) uninstall_all ;;
    status) status_s ;;
    logs) logs_s ;;
    print-links) print_links ;;
    rotate-secret) rotate_secret ;;
    health) health ;;
    *) usage; exit 1 ;;
  esac
}
main "$@"
