import subprocess
import os
import sys
from prettytable import PrettyTable
import platform

IS_WINDOWS = platform.system().lower() == "windows"
IS_LINUX = platform.system().lower() == "linux"

# ANSI color codes
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
RESET = "\033[0m"

# Global OPSEC and Proxychains flags
OPSEC_ENABLED = False
USE_PROXYCHAINS = False

# OPSEC flags for stealth scanning
OPSEC_FLAGS = [
    "-Pn",                  # No ping (skip host discovery)
    "--randomize-hosts",    # Randomize target order
    "--data-length", "50",  # Obfuscate packet size
    "--source-port", "53",  # Spoof source port as DNS
    "-T2",                  # Slow timing to evade IDS
    "--max-retries", "1",   # Fewer retries
    "--max-rate", "100",    # Limit packet sending rate
]

def clear_screen(args=None):
    os.system('cls' if IS_WINDOWS else 'clear')

def set_terminal_title(title):
    if IS_WINDOWS:
        os.system(f"title {title}")
    else:
        # For Linux/macOS terminals supporting ANSI escape codes:
        sys.stdout.write(f"\x1b]2;{title}\x07")
        sys.stdout.flush()

def show_help(args=None):
    print(f"""{GREEN}
Available commands:
  {YELLOW}scan <ip>{GREEN}           - Single host SYN scan
  {YELLOW}scan-m <ip1> <ip2> <ip3>{GREEN}  - Multiple hosts SYN scan
  {YELLOW}scan-s <subnet>{GREEN}     - Scan entire subnet (CIDR) SYN scan
  {YELLOW}scan-f <filename>{GREEN}   - Scan targets from file SYN scan
  {YELLOW}detect-v <ip>{GREEN}       - Service/version detection
  {YELLOW}detect-o <ip>{GREEN}       - OS fingerprinting
  {YELLOW}detect-a <ip>{GREEN}       - Aggressive scan
  {YELLOW}detect-s <ip>{GREEN}       - Default scripts & traceroute
  {YELLOW}osint-r <ip>{GREEN}        - Reverse DNS
  {YELLOW}osint-w <ip>{GREEN}        - Whois lookup
  {YELLOW}osint-h <ip>{GREEN}        - HTTP headers
  {YELLOW}osint-e <ip>{GREEN}        - Emails & ASN info
  {YELLOW}vuln-s <ip>{GREEN}         - Run vulnerability scripts
  {YELLOW}vuln-smb <ip>{GREEN}       - Scan SMB vulns
  {YELLOW}vuln-http <ip>{GREEN}      - Scan HTTP vulns
  {YELLOW}vuln-udp <ip>{GREEN}       - UDP vulnerability scan
  {YELLOW}vuln-tcp <ip>{GREEN}       - TCP vulnerability scan
  {YELLOW}fullscan <ip>{GREEN}       - Aggressive full scan + vuln scripts
  {YELLOW}allports <ip>{GREEN}       - Scan all ports
  {YELLOW}opsec <on|off>{GREEN}      - Enable or disable OPSEC mode
  {YELLOW}proxychains <on|off>{GREEN} - Enable or disable proxychains mode
  {YELLOW}clear{GREEN}                - Clear the terminal screen
  {YELLOW}help{GREEN}                 - Show this help menu
  {YELLOW}exit{GREEN}                 - Exit the tool
{RESET}""")

def exit_tool(args=None):
    print(f"{CYAN}Goodbye! Stay stealthy!{RESET}")
    sys.exit(0)

def build_command(base_cmd):
    cmd = []
    if USE_PROXYCHAINS:
        cmd.append("proxychains")
    cmd.extend(base_cmd)
    if OPSEC_ENABLED and ("nmap" in base_cmd[0]):
        cmd.extend(OPSEC_FLAGS)
    return cmd

from prettytable import PrettyTable  # Make sure this is imported

def run_scan(cmd, target):
    print(f"{CYAN}[*] Starting scan on {target}...{RESET}")
    try:
        # Add grepable output for parsing
        cmd += ["-oG", "-"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            print(f"{RED}[✗] Scan on {target} failed to execute.{RESET}")
            return

        # Parse open ports
        open_ports = []
        for line in result.stdout.splitlines():
            if line.startswith("Host:") and "Ports:" in line:
                ports_section = line.split("Ports:")[1].strip()
                ports = ports_section.split(", ")
                for port_info in ports:
                    port_parts = port_info.split("/")
                    if len(port_parts) >= 5 and port_parts[1] == "open":
                        port = port_parts[0]
                        state = port_parts[1]
                        service = port_parts[4] if len(port_parts) > 4 else "unknown"
                        open_ports.append((port, state, service))

        # Print table
        table = PrettyTable()
        table.field_names = [f"{CYAN}Port{RESET}", f"{CYAN}State{RESET}", f"{CYAN}Service{RESET}"]

        if open_ports:
            for port, state, service in open_ports:
                table.add_row([port, f"{GREEN}{state}{RESET}", service])
            print(table)
        else:
            print(f"{YELLOW}[!] No open ports found on {target}.{RESET}")

        print(f"{GREEN}[✓] Scan on {target} completed successfully.{RESET}")

    except Exception as e:
        print(f"{RED}[✗] Scan on {target} failed: {e}{RESET}")

# Scan functions

def scan_single(args):
    if not args:
        print(f"{RED}Usage: scan <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-sS", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def multiple_scan(args):
    if len(args) < 1:
        print(f"{RED}Usage: scan-m <ip1> <ip2> <ip3>{RESET}")
        return
    targets = args[:3]
    base_cmd = ["nmap", "-sS"] + targets
    cmd = build_command(base_cmd)
    run_scan(cmd, ", ".join(targets))

def subnet_scan(args):
    if not args:
        print(f"{RED}Usage: scan-s <subnet>{RESET}")
        return
    subnet = args[0]
    base_cmd = ["nmap", "-sS", subnet]
    cmd = build_command(base_cmd)
    run_scan(cmd, subnet)

def scan_file(args):
    if not args:
        print(f"{RED}Usage: scan-f <filename>{RESET}")
        return
    file = args[0]
    base_cmd = ["nmap", "-sS", "-iL", file]
    cmd = build_command(base_cmd)
    run_scan(cmd, f"targets from {file}")

def version_scan(args):
    if not args:
        print(f"{RED}Usage: detect-v <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-sS", "-sV", "--version-light", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def finger(args):
    if not args:
        print(f"{RED}Usage: detect-o <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-O", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def full_scan(args):
    if not args:
        print(f"{RED}Usage: detect-a <ip> or fullscan <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-A", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def detect_scripts(args):
    if not args:
        print(f"{RED}Usage: detect-s <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-sC", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def reverse_dns(args):
    if not args:
        print(f"{RED}Usage: osint-r <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-R", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def whois(args):
    if not args:
        print(f"{RED}Usage: osint-w <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "--script", "whois-ip", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def headers(args):
    if not args:
        print(f"{RED}Usage: osint-h <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "--script", "http-headers", "-p", "80,443", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def whois_emails(args):
    if not args:
        print(f"{RED}Usage: osint-e <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "--script", "whois-ip,asn-query", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def vuln(args):
    if not args:
        print(f"{RED}Usage: vuln-s <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "--script", "vuln", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def http_vuln(args):
    if not args:
        print(f"{RED}Usage: vuln-http <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "--script", "http-vuln*", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def udp(args):
    if not args:
        print(f"{RED}Usage: vuln-udp <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-sU", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def tcp(args):
    if not args:
        print(f"{RED}Usage: vuln-tcp <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-sT", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def smb(args):
    if not args:
        print(f"{RED}Usage: vuln-smb <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "--script", "smb-vuln*", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

def all_port(args):
    if not args:
        print(f"{RED}Usage: allports <ip>{RESET}")
        return
    ipa = args[0]
    base_cmd = ["nmap", "-sS", "-p-", "-T1", ipa]
    cmd = build_command(base_cmd)
    run_scan(cmd, ipa)

# OPSEC and Proxychains toggle commands

def set_opsec_mode(args):
    global OPSEC_ENABLED
    if len(args) == 0:
        print(f"OPSEC mode is currently {'ON' if OPSEC_ENABLED else 'OFF'}")
        return
    mode = args[0].lower()
    if mode == "on":
        OPSEC_ENABLED = True
        print(f"{GREEN}OPSEC mode enabled.{RESET}")
    elif mode == "off":
        OPSEC_ENABLED = False
        print(f"{YELLOW}OPSEC mode disabled.{RESET}")
    else:
        print(f"{RED}Usage: opsec <on|off>{RESET}")

def set_proxychains_mode(args):
    global USE_PROXYCHAINS
    if len(args) == 0:
        print(f"Proxychains mode is currently {'ON' if USE_PROXYCHAINS else 'OFF'}")
        return
    mode = args[0].lower()
    if mode == "on":
        USE_PROXYCHAINS = True
        print(f"{GREEN}Proxychains enabled.{RESET}")
    elif mode == "off":
        USE_PROXYCHAINS = False
        print(f"{YELLOW}Proxychains disabled.{RESET}")
    else:
        print(f"{RED}Usage: proxychains <on|off>{RESET}")

def main():
    commands = {
        "scan": scan_single,
        "scan-m": multiple_scan,
        "scan-s": subnet_scan,
        "scan-f": scan_file,
        "detect-v": version_scan,
        "detect-o": finger,
        "detect-a": full_scan,
        "detect-s": detect_scripts,
        "osint-r": reverse_dns,
        "osint-w": whois,
        "osint-h": headers,
        "osint-e": whois_emails,
        "vuln-s": vuln,
        "vuln-smb": smb,
        "vuln-http": http_vuln,
        "vuln-udp": udp,
        "vuln-tcp": tcp,
        "fullscan": full_scan,
        "allports": all_port,
        "opsec": set_opsec_mode,
        "proxychains": set_proxychains_mode,
        "clear": clear_screen,
        "help": show_help,
        "exit": exit_tool,
    }
    set_terminal_title("7rootOPSECScanner – Stealth Recon Tool")
    clear_screen()
    print(f"{CYAN}Welcome to 7rootOPSECScanner! Type 'help' for commands.{RESET}")
    while True:
        try:
            user_input = input(f"{GREEN}shade-scanner> {RESET}").strip().split()
        except (EOFError, KeyboardInterrupt):
            print()
            exit_tool()

        if not user_input:
            continue

        cmd = user_input[0]
        args = user_input[1:]

        func = commands.get(cmd)
        if func:
            func(args)
        else:
            print(f"{RED}Unknown command: {cmd}. Type 'help' for commands.{RESET}")

if __name__ == "__main__":
    print(f"Running on {'Windows' if IS_WINDOWS else 'Linux' if IS_LINUX else 'Other OS'}")
    main()
