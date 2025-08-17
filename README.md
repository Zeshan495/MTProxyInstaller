# MTX Proxy Installer Ubuntu/Debian (22.04/24.04+)

A one-file **MTProto Proxy installer/manager**.

## Features
- Install **Official C MTProxy** (default) or **Python mtprotoproxy** (with Python 3.10 venv).
- Systemd service setup (`MTProxy.service` or `mtprotoproxy.service`).
- Auto-updater timer for Telegram configs (`proxy-secret`, `proxy-multi.conf`).
- Prints **three share links**: normal, `dd` padding, and `ee` FakeTLS.
- Easy management: `status`, `logs`, `rotate-secret`, `print-links`, `uninstall`.

## Quickstart

```bash
# Clone repo
git clone https://github.com/Zeshan495/MTProxyInstaller
cd MTProxyInstaller
chmod +x mtx.sh

# 2) Install the official C proxy on port 8443 (recommended)
sudo ./mtx.sh install --impl c --port 8443 --tls www.microsoft.com --ad-tag
# Replace 1234567890abcdef1234567890abcdef with your actual promo tag (32 hex chars) from @MTProxybot.

#    …or install the Python proxy (uses a Python 3.10 venv)
sudo ./mtx.sh install --impl python --port 8443 --tls www.microsoft.com

# 3) See status / logs / links later
sudo ./mtx.sh status
sudo ./mtx.sh logs
sudo ./mtx.sh print-links
sudo ./mtx.sh rotate-secret

# 4) Rotate secret safely (auto restarts the service)
sudo bash mtx.sh rotate-secret

# 5) Uninstall everything cleanly
sudo ./mtx.sh uninstall
