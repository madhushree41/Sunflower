import os, time, shutil, sys, random, string
from pathlib import Path
import winreg

SANDBOX = Path(r"C:\sandbox")

def reg_set_test(name, value):
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\TestApp")
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        winreg.CloseKey(key)
        print(f"[REG_SET] HKCU\\Software\\TestApp\\{name}={value}")  # collector parses this
    except Exception as e:
        print(f"[REG_ERR] {e}")

def benign_installer_like():
    root = SANDBOX / "benign_installer"; root.mkdir(parents=True, exist_ok=True)
    for i in range(5):
        f = root / f"file_{i}.txt"
        f.write_text("installer data")
        time.sleep(0.2)
    reg_set_test("InstallPath", str(root))
    time.sleep(0.5)
    # modify a couple of files
    for i in range(2):
        f = root / f"file_{i}.txt"
        f.write_text("updated")
        time.sleep(0.2)

def wiper_like():
    root = SANDBOX / "wiper"; root.mkdir(parents=True, exist_ok=True)
    files = []
    for i in range(10):
        f = root / f"a_{i}.log"
        f.write_text("temp")
        files.append(f)
    time.sleep(1.0)
    for f in files:
        try: f.unlink()
        except: pass
    shutil.rmtree(root, ignore_errors=True)

def ransomware_like():
    root = SANDBOX / "ransom"; root.mkdir(parents=True, exist_ok=True)
    for i in range(20):
        (root / f"doc_{i}.txt").write_text("important data")
    time.sleep(0.5)
    # "encrypt" = rename + add .enc, write junk
    for p in root.glob("*.txt"):
        newp = p.with_suffix(".txt.enc")
        newp.write_text("".join(random.choice(string.ascii_letters) for _ in range(200)))
        p.unlink()
        time.sleep(0.05)

def beacon_like():
    # no real network; just emit DNS lines for the collector
    domains = ["cdn-updates.example", "telemetry.service", "analytics.host"]
    for d in domains:
        print(f"[DNS] {d}")
        time.sleep(0.4)
    # simulate staging
    root = SANDBOX / "beacon"; root.mkdir(parents=True, exist_ok=True)
    (root / "stage.bin").write_text("stub")

def persistence_like():
    root = SANDBOX / "persist"; root.mkdir(parents=True, exist_ok=True)
    reg_set_test("Run", str(root / "agent.exe"))

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "benign"
    SANDBOX.mkdir(parents=True, exist_ok=True)
    if mode == "benign": benign_installer_like()
    elif mode == "wiper": wiper_like()
    elif mode == "ransom": ransomware_like()
    elif mode == "beacon": beacon_like()
    elif mode == "persist": persistence_like()
    else: benign_installer_like()

if __name__ == "__main__":
    main()
