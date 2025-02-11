import argparse
import os
import sys
import subprocess
import requests
import tempfile
import shutil
import stat
import json

DEBUG = False

def log_info(message):
    print(f"[+] {message}")

def log_error(message):
    print(f"[-] {message}")

def dprint(message):
    if DEBUG:
        print(f"[DEBUG] {message}")

def get_latest_gitleaks_release():
    url = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
    dprint(f"Requesting latest release from: {url}")
    response = requests.get(url)
    if response.status_code != 200:
        log_error(f"Failed to retrieve latest gitleaks release. Status code: {response.status_code}")
        sys.exit(1)
    release_data = response.json()
    dprint(f"Release data retrieved: {release_data}")
    return release_data

def select_asset_for_platform(release_data):
    current_platform = sys.platform
    dprint(f"Current platform: {current_platform}")
    if current_platform.startswith("linux"):
        os_key = "linux"
    elif current_platform == "darwin":
        os_key = "darwin"
    elif current_platform.startswith("win"):
        os_key = "windows"
    else:
        log_error(f"Unsupported operating system: {current_platform}")
        sys.exit(1)
    assets = release_data.get("assets", [])
    for asset in assets:
        asset_name = asset.get("name", "").lower()
        if os_key in asset_name and (("amd64" in asset_name) or ("x86_64" in asset_name) or ("x64" in asset_name)):
            dprint(f"Selected asset: {asset.get('name', '')}")
            return asset.get("browser_download_url")
    log_error(f"No asset found for platform {os_key}")
    sys.exit(1)

def download_file(url, dest_path):
    dprint(f"Downloading: {url}")
    log_info(f"Downloading gitleaks.")
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(dest_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    dprint(f"File downloaded to: {dest_path}")

def run_gitleaks(gitleaks_path, report_path, no_git, repo_location):
    cmd = [gitleaks_path, "detect"]
    if no_git:
        cmd.append("--no-git")
    cmd.extend(["-f", "json", "-r", report_path])
    log_info(f"Executing gitleaks.")
    dprint(f"Full command: {cmd} in directory: {repo_location}")
    result = subprocess.run(cmd, cwd=repo_location, capture_output=True, text=True, check=False)
    dprint(f"Command result - Return code: {result.returncode}, STDOUT: {result.stdout}, STDERR: {result.stderr}")
    if result.returncode not in (0, 1):
        log_error("Error executing gitleaks:")
        log_error(f"Return code: {result.returncode}")
        log_error(f"Output: {result.stdout}")
        log_error(f"Error: {result.stderr}")
        sys.exit(result.returncode)
    dprint(f"Report generated at: {report_path}")

def extract_context_for_finding(finding, repo_location):
    commit = finding.get("Commit")
    file_path = finding.get("File")
    start_line = finding.get("StartLine")
    end_line = finding.get("EndLine")
    dprint(f"Extracting context for file: {file_path}, commit: {commit}, lines: {start_line}-{end_line}")
    if not commit:
        full_path = os.path.join(repo_location, file_path)
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            lines = content.splitlines()
        except Exception as e:
            log_error(f"Unable to retrieve content of file '{file_path}' in current state: {e}")
            return None
    else:
        try:
            result = subprocess.check_output(
                ["git", "show", f"{commit}:{file_path}"],
                stderr=subprocess.DEVNULL,
                cwd=repo_location
            )
            content = result.decode("utf-8", errors="replace")
            lines = content.splitlines()
        except subprocess.CalledProcessError:
            log_error(f"Unable to retrieve content of file '{file_path}' at commit '{commit}'.")
            return None
    context_start = max(0, start_line - 1 - 3)
    context_end = min(len(lines), end_line - 1 + 3 + 1)
    context = lines[context_start:context_end]
    dprint(f"Extracted context (lines {context_start + 1} to {context_end}): {context}")
    return context

def main():
    global DEBUG
    parser = argparse.ArgumentParser(
        description="Gitleaks wrapper with context extraction from a JSON report."
    )
    parser.add_argument("--no-cleanup", action="store_true", help="Do not remove temporary files after execution.")
    parser.add_argument("--no-git", action="store_true", help="Disable recursive scanning of repository history (use the '--no-git' flag).")
    parser.add_argument("--repo", default=".", help="Path of the cloned repository (default: '.').")
    parser.add_argument("-v", "--debug", action="store_true", help="Habilita o modo de depuração com informações adicionais.")
    args = parser.parse_args()
    DEBUG = args.debug
    repo_location = args.repo
    if not os.path.isdir(os.path.join(repo_location, ".git")):
        log_info(f"Warning: '.git' not found in {repo_location} - automatically enabling '--no-git' option.")
        args.no_git = True
    tmp_dir = tempfile.mkdtemp(prefix="gitleaks_")
    dprint(f"Temporary directory: {tmp_dir}")
    try:
        release_data = get_latest_gitleaks_release()
        download_url = select_asset_for_platform(release_data)
        gitleaks_asset = os.path.join(tmp_dir, "gitleaks_asset")
        download_file(download_url, gitleaks_asset)
        if download_url.endswith(".zip"):
            import zipfile
            with zipfile.ZipFile(gitleaks_asset, "r") as zip_ref:
                zip_ref.extractall(tmp_dir)
            exe_path = os.path.join(tmp_dir, "gitleaks")
            if not os.path.exists(exe_path):
                for root, dirs, files in os.walk(tmp_dir):
                    if "gitleaks" in files:
                        exe_path = os.path.join(root, "gitleaks")
                        break
            if not os.path.exists(exe_path):
                log_error("Failed to locate the gitleaks binary extracted from ZIP.")
                sys.exit(1)
            gitleaks_bin = exe_path
        elif download_url.endswith(".tar.gz") or download_url.endswith(".tgz"):
            import tarfile
            with tarfile.open(gitleaks_asset, "r:gz") as tar_ref:
                tar_ref.extractall(tmp_dir)
            exe_path = os.path.join(tmp_dir, "gitleaks")
            if not os.path.exists(exe_path):
                for root, dirs, files in os.walk(tmp_dir):
                    if "gitleaks" in files:
                        exe_path = os.path.join(root, "gitleaks")
                        break
            if not os.path.exists(exe_path):
                log_error("Failed to locate the gitleaks binary extracted from TAR.GZ.")
                sys.exit(1)
            gitleaks_bin = exe_path
        else:
            gitleaks_bin = gitleaks_asset
        st = os.stat(gitleaks_bin)
        os.chmod(gitleaks_bin, st.st_mode | stat.S_IEXEC)
        dprint(f"Execution permission granted for: {gitleaks_bin}")
        report_path = os.path.join(tmp_dir, "gitleaks-report.json")
        run_gitleaks(gitleaks_bin, report_path, args.no_git, repo_location)
        with open(report_path, "r", encoding="utf-8") as f:
            try:
                findings = json.load(f)
            except json.JSONDecodeError as e:
                log_error(f"Error decoding JSON report: {e}")
                findings = []
        if not findings:
            log_info("No vulnerabilities found.")
        else:
            for finding in findings:
                context = extract_context_for_finding(finding, repo_location)
                finding["context"] = context if context is not None else []
            output_file = "gitleaks-context.json"
            with open(output_file, "w", encoding="utf-8") as f_out:
                json.dump(findings, f_out, indent=4, ensure_ascii=False)
            log_info(f"Output file with contexts saved at: {output_file}")
    finally:
        if args.no_cleanup:
            log_info(f"No cleanup mode activated. Temporary directory will not be removed: {tmp_dir}")
        else:
            dprint(f"Removing temporary directory: {tmp_dir}")
            log_info(f"Cleaning up temporary files.")
            shutil.rmtree(tmp_dir)

if __name__ == "__main__":
    main()
