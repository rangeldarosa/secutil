# Gitleaks.py

This script serves as a *wrapper* for the [Gitleaks](https://github.com/gitleaks/gitleaks) tool, designed to identify vulnerabilities and extract relevant context from Git repositories.

## Features

- **Automatic Download:** Retrieves the latest version of Gitleaks from GitHub and downloads the appropriate asset for your platform (Linux, macOS, or Windows).
- **Permission Setup:** Automatically sets the execution permissions for the downloaded binary.
- **Context Extraction:** After execution, extracts context lines (a few lines before and after) from the sections identified as vulnerable.
- **Customizable Parameters:** Allows you to modify execution, for example, by disabling Git history scanning with `--no-git`, retaining temporary files with `--no-cleanup`, or passing the repository path with `--repo`.
- **JSON Output:** The results, along with the contextual information, are saved in the file `gitleaks-context.json` in the current directory.

## Execution

You can run the script directly from the internet using the command below:

```bash
sudo apt update && sudo apt install python3 python3-pip -y && pip3 install requests --break-system-packages && curl -s https://raw.githubusercontent.com/rangeldarosa/secutil/main/gitleaks.py | python3 -
```

To include execution parameters, such as disabling Git history analysis using `--no-git`, use:

```bash
sudo apt update && sudo apt install python3 python3-pip -y && pip3 install requests --break-system-packages && curl -s https://raw.githubusercontent.com/rangeldarosa/secutil/main/gitleaks.py | python3 - --no-git
```

Alternatively, you can download the script using curl or wget, save it locally, adjust the execution permissions (e.g., with chmod +x), and run it with Python:

```bash
curl -s https://raw.githubusercontent.com/rangeldarosa/secutil/main/gitleaks.py -o gitleaks.py  
chmod +x gitleaks.py
pip3 install requests
python3 gitleaks.py
```

Ensure you have Python3, pip, and the requests library installed for the script to function correctly.
