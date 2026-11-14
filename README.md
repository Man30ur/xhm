<p align="center">
  <img src="docs/screenshots/logo.png" alt="XHM logo" width="96" height="96">
</p>

<h1 align="center">XHM</h1>

<p align="center">
  <strong>Modern Linux Proxy &amp; VPN Manager</strong><br>
  <em>مدیریت مدرن پروکسی و VPN برای لینوکس</em>
</p>

<p align="center">
  GUI · Terminal UI · System Proxy · Full-System TUN (<code>xhm-tun</code>)<br>
  VLESS · VMess · Trojan · Shadowsocks · SOCKS · SSH
</p>

<p align="center">
  <a href="#english">English</a> ·
  <a href="#فارسی">فارسی</a>
</p>

---

<p align="center">
  <img src="docs/screenshots/gui-dashboard.png" alt="XHM GUI dashboard" width="900">
</p>

<p align="center">
  <img src="docs/screenshots/cli-status.png" alt="XHM CLI status" width="640">
</p>

---

<a id="english"></a>
## English

### What is XHM?
XHM is a modern Linux proxy client with a desktop GUI and a terminal UI.  
Connect to your servers, enable system proxy, or route **all system traffic** through built-in **TUN Mode** (`xhm-tun`) powered by `sing-box`.

### Features
- **Multi-protocol:** VLESS, VMess, Trojan, Shadowsocks, SOCKS, SSH (`ssh://`, `npvt-ssh://`)
- **Desktop GUI** (`xhm-gui`) and **Terminal UI / CLI** (`xhm`)
- **GNOME system proxy** with sensible bypasses for LAN / localhost
- **Full-system TUN Mode** (`xhm-tun`) — passwordless after install
- **Live traffic** speeds + totals, ping tests, analytics, subscriptions, QR share

### Requirements
Ubuntu/Debian, Fedora, Arch, or openSUSE.  
`./install.sh` installs dependencies automatically (Python 3.8+, `curl`, `xray`, `sing-box`, …).

### Install

**Option 1 — One-command install (no manual clone needed):**
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Man30ur/xhm/main/install.sh)"
```

**Option 2 — Clone & install in one line:**
```bash
git clone https://github.com/Man30ur/xhm.git && ./xhm/install.sh
```

By default the installer:
- grants `cap_net_admin` to `sing-box` (passwordless TUN)
- installs a polkit rule for TUN DNS via `systemd-resolved`
- links `xhm` and `xhm-gui` into `/usr/local/bin` so commands work immediately

Optional flags:
```bash
./install.sh --no-grant-tun-cap   # skip passwordless TUN setup
./install.sh --no-deps            # copy app files only
./install.sh --user-only          # install to ~/.local only (no /usr/local/bin symlinks)
```

### Usage & Updates
```bash
xhm-gui           # Desktop GUI (shows an "Update" badge when a new Git commit is out)
xhm               # Terminal UI / interactive menu
xhm status
xhm tun on
xhm tun off
xhm update --check
xhm update        # Pull latest clean Git updates & sync local files
```

### Notes
- Connect to a server in XHM **before** enabling TUN Mode.
- Your private configs (`custom_configs.json`, subscriptions, passwords) stay local and are gitignored.

---

<a id="فارسی"></a>
## فارسی

### XHM چیست؟
یک کلاینت مدرن پروکسی برای لینوکس با **رابط گرافیکی** و **ترمینال**.  
به سرورها وصل شو، System Proxy را روشن کن، یا کل ترافیک سیستم را با **حالت TUN** (`xhm-tun`) از مسیر پروکسی رد کن.

### امکانات
- پشتیبانی از **VLESS / VMess / Trojan / Shadowsocks / SOCKS / SSH**
- GUI دسکتاپ (`xhm-gui`) و منوی ترمینال (`xhm`)
- پروکسی سیستم GNOME
- **TUN سراسری** (`xhm-tun`) — بعد از نصب بدون پسورد تکراری
- تشخیص خودکار نسخه جدید از گیت در رابط گرافیکی و CLI (`xhm update`)
- سرعت لحظه‌ای، پینگ، آنالیتیکس، سابسکریپشن، QR

### نصب

**روش اول — نصب تک‌دستوری (خودکار کلون و نصب می‌کند):**
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Man30ur/xhm/main/install.sh)"
```

**روش دوم — کلون و نصب در یک خط:**
```bash
git clone https://github.com/Man30ur/xhm.git && ./xhm/install.sh
```

به‌صورت پیش‌فرض:
- دسترسی `cap_net_admin` به `sing-box` داده می‌شود
- قانون polkit برای DNS حالت TUN نصب می‌شود
- دستورهای `xhm` و `xhm-gui` در `/usr/local/bin` لینک می‌شوند تا بلافاصله در ترمینال قابل اجرا باشند

### استفاده و آپدیت
```bash
xhm-gui           # رابط گرافیکی (در صورت وجود آپدیت، نشانگر Update نمایش داده می‌شود)
xhm               # منوی ترمینال
xhm status
xhm tun on
xhm tun off
xhm update --check
xhm update        # دریافت و اعمال امن آخرین نسخه از گیت
```

### نکته
اول به یک سرور وصل شو، بعد TUN را روشن کن.  
فایل‌های شخصی کانفیگ داخل گیت نمی‌روند.

---

## License
Use freely for personal projects. Contributions welcome via Pull Request.
