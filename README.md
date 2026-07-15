# HTB Smarthire

Writeup and exploit tooling for the HackTheBox **Smarthire** machine.

## Key Target File: `/opt/tools/mlflow_ctl/mlflowctl.py`

This script is central to the privilege escalation chain. The full source:

```python
#!/usr/bin/env python3
"""
MLFLOW-CTL: Operational interface for managing the MLflow service.
Supports a pluggable extension model for environment-specific logic.
For changes or plugin requests, please contact the Platform Team.
"""

from pathlib import Path
import sys
import site

BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

# make plugins importable
for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def print_usage():
    print("Usage: mlflowctl.py [status|backup-models|restart]")
    sys.exit(1)

def main():
    import mlflow_actions, backup_models

    if len(sys.argv) < 2:
        print_usage()

    action = sys.argv[1]

    if action == "status":
        mlflow_actions.check_status()
    elif action == "backup-models":
        print("[*] Running backup via backup_models plugin...")
        backup_models.run()
    elif action == "restart":
        mlflow_actions.restart()
    else:
        print(f"[!] Unknown action: {action}")
        print_usage()

if __name__ == "__main__": main()
```

The vulnerability: `site.addsitedir()` processes `.pth` files in plugin directories. Lines starting with `import` are `exec()`'d with root privileges. Since `svcweb` can write to the `plugins/dev/` directory (via the `devs` group), planting a `.pth` file that imports a malicious module yields code execution as root.

## Credits

- **CVE-2024-37054-MLflow-reverse-shell** — based on [Spydomain/CVE-2024-37054-MLflow-reverse-shell](https://github.com/Spydomain/CVE-2024-37054-MLflow-reverse-shell)
- **CVE-2024-37054-PoC** — based on [jimmexploit/CVE-2024-37054-PoC](https://github.com/jimmexploit/CVE-2024-37054-PoC)
