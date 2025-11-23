# 🛡️ 7rootOPSECScanner

A fast, stealthy, and customizable Nmap-based host scanning tool with **OPSEC** & **Proxychains** support.

![](https://img.shields.io/badge/status-active-brightgreen) ![](https://img.shields.io/badge/python-3.8+-blue) ![](https://img.shields.io/badge/license-MIT-green)

---

## 📖 Overview

**7rootOPSECScanner** is a Python CLI tool that wraps Nmap scans in a clean and modern interface, providing advanced features for stealth reconnaissance.

🔹 **OPSEC Mode**: Adds stealth flags to evade detection systems.
🔹 **Proxychains Support**: Route scans through proxies for anonymity.
🔹 **Clean CLI**: Custom banners and simplified commands.
🔹 Designed for **penetration testers** and **sysadmins**.

---

## ⚡ Features

✅ **Single and multiple host scans** (`scan`, `scan-m`)
✅ **Subnet scanning** (`scan-s`)
✅ **File-based scanning** (`scan-f`)
✅ **OS detection & service version detection** (`detect-o`, `detect-v`)
✅ **Vulnerability scans** (`vuln-s`)
✅ **OPSEC mode toggle** for stealth
✅ **Proxychains toggle** for anonymity
✅ Clean banners for start and end of scans
✅ Built-in `help` menu

---


## 🖥️ Installation

### 🐧 On Linux

1. **Update your package lists** (recommended):

   ```bash
   sudo apt update
   ```

2. **Install Nmap and Proxychains**:

   ```bash
   sudo apt install nmap proxychains
   ```

3. **Clone this repository**:

   ```bash
   git clone https://github.com/<your-username>/ShadeScanner.git
   cd ShadeScanner
   ```

4. **Install Python dependencies** (make sure you have Python 3 and pip):

   ```bash
   pip3 install -r requirements.txt
   ```

5. **Run the tool**:

   ```bash
   python3 shade_scanner.py
   ```

**Troubleshooting:**

* If `proxychains` commands don’t work, ensure your proxychains config (`/etc/proxychains.conf`) is set up correctly.
* For permission errors, try running with `sudo` only if necessary.

---



---

### 🪟 On Windows

1. **Download the repository as ZIP** from GitHub and extract it anywhere you want.

2. **Download and install [Nmap for Windows](https://nmap.org/download.html#windows)**

   * Make sure to add Nmap to your system PATH during installation.

3. **Make sure you have Python 3 installed** (download from [https://python.org](https://python.org)) and added to your system PATH.

4. **Open Command Prompt or PowerShell**, navigate to the extracted folder, and run:

   ```powershell
   python shade_scanner.py
   ```

**Note:**

* Proxychains is **not available on Windows**. Use other anonymity tools like VPNs if needed.

---





## 🚀 Usage

### ✅ Commands

| Command                    | Description                            |
| -------------------------- | -------------------------------------- |
| `scan <ip>`                | Single host SYN scan                   |
| `scan-m <ip1> <ip2> <ip3>` | Multiple hosts SYN scan                |
| `scan-s <subnet>`          | Scan entire subnet (CIDR)              |
| `scan-f <filename>`        | Scan targets from a file               |
| `detect-v <ip>`            | Service/version detection              |
| `detect-o <ip>`            | OS fingerprinting                      |
| `detect-a <ip>`            | Aggressive scan                        |
| `detect-s <ip>`            | Default scripts & traceroute           |
| `osint-r <ip>`             | Reverse DNS lookup                     |
| `osint-w <ip>`             | Whois lookup                           |
| `osint-h <ip>`             | HTTP headers enumeration               |
| `osint-e <ip>`             | Whois emails & ASN info                |
| `vuln-s <ip>`              | Run all Nmap vulnerability scripts     |
| `vuln-smb <ip>`            | Scan for SMB vulnerabilities           |
| `vuln-http <ip>`           | Scan for HTTP vulnerabilities          |
| `vuln-udp <ip>`            | UDP vulnerability scan                 |
| `vuln-tcp <ip>`            | TCP vulnerability scan                 |
| `fullscan <ip>`            | Aggressive full scan with vuln scripts |
| `allports <ip>`            | Scan all ports on target               |
| `opsec-on`                 | Enable OPSEC mode (stealth scan flags) |
| `opsec-off`                | Disable OPSEC mode                     |
| `proxy-on`                 | Enable Proxychains for all scans       |
| `proxy-off`                | Disable Proxychains                    |
| `clear`                    | Clear the terminal screen              |
| `help`                     | Show help menu                         |
| `exit`                     | Exit the tool                          |


### 🌟 Example Session

Here’s what a scan looks like in 7rootOPSECScanner :

![Example Session](https://media.discordapp.net/attachments/1378874912139116727/1393969412297457925/image.png?ex=68751aae\&is=6873c92e\&hm=4fd42bac0e35a791a447c058b025d1c5dcf88b26c5f140bd4a2306dd5ccb7739&=\&format=webp\&quality=lossless)

---

## 🛡️ OPSEC Mode

When enabled, OPSEC mode adds the following flags:

* `-Pn` → Skip ping probes (no host discovery)
* `--randomize-hosts` → Scan hosts in random order
* `--data-length 50` → Obfuscate packet size
* `-T2` → Slow timing template for stealth
* `--max-retries 1` → Minimize retries

Enable OPSEC:

```bash
shade-scanner> opsec-on
```

Disable OPSEC:

```bash
shade-scanner> opsec-off
```

---

## 🌐 Proxychains Support

Route all scans through proxies with Proxychains.

Enable Proxychains:

```bash
shade-scanner> proxy-on
```

Disable Proxychains:

```bash
shade-scanner> proxy-off
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

** (sh4de)**
🔗 [GitHub](https://github.com/7rootsec)


##  📞 Contact & Support
If you find any bugs, have questions, or want to suggest improvements, feel free to reach out to me:

Instagram: @youssef_amarti1

Discord: .sh4de.

I’m happy to help and improve the tool! ✌️


---

