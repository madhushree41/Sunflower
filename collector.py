import json, time, uuid, threading, subprocess, sys, os
from pathlib import Path
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SANDBOX = Path(r"C:\sandbox")
RUNS = Path("data/runs"); RUNS.mkdir(parents=True, exist_ok=True)

class FSHandler(FileSystemEventHandler):
    def __init__(self, timeline):
        self.timeline = timeline
        self.t0 = time.time()
    def _t(self): return round(time.time() - self.t0, 3)
    def on_created(self, e):
        ev = {"t": self._t(), "type": "folder_create" if e.is_directory else "file_create", "path": e.src_path}
        self.timeline.append(ev)
    def on_deleted(self, e):
        ev = {"t": self._t(), "type": "folder_delete" if e.is_directory else "file_delete", "path": e.src_path}
        self.timeline.append(ev)
    def on_modified(self, e):
        if not e.is_directory:
            self.timeline.append({"t": self._t(), "type": "file_modify", "path": e.src_path})

def track_process(pid, timeline, rollups, stop_flag):
    cpu_max = 0.0
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return
    while not stop_flag["stop"]:
        try:
            cpu = p.cpu_percent(interval=0.2) 
            cpu_max = max(cpu_max, cpu)
            # child spawns
            for c in p.children(recursive=False):
                timeline.append({"t": time.time()-stop_flag["t0"], "type": "proc_spawn",
                                 "child": c.name(), "child_pid": c.pid})
            # connections
            for c in p.connections(kind='inet'):
                if c.raddr:
                    dst = f"{c.raddr.ip}:{c.raddr.port}"
                    timeline.append({"t": time.time()-stop_flag["t0"], "type":"net_connect", "dst": dst})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
    rollups["cpu_max"] = round(cpu_max, 2)

def run_and_collect(label, cmdline):

    SANDBOX.mkdir(parents=True, exist_ok=True)
   
    proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    pid = proc.pid

    sample_id = str(uuid.uuid4())
    timeline = []
    rollups = {
      "file_create":0, "file_delete":0, "file_modify":0,
      "folder_create":0, "folder_delete":0,
      "reg_set":0, "reg_delete":0,
      "dns_query":0, "net_connect":0,
      "proc_spawn":0, "cpu_max":0.0, "duration_s":0.0, "unique_exts":0
    }

    handler = FSHandler(timeline)
    observer = Observer(); observer.schedule(handler, str(SANDBOX), recursive=True); observer.start()


    stop_flag = {"stop": False, "t0": time.time()}
    t = threading.Thread(target=track_process, args=(pid, timeline, rollups, stop_flag)); t.start()

    # Parse stdout for registry/dns notes written by the sample itself
    try:
        for line in proc.stdout:
            line=line.strip()
            if line.startswith("[REG_SET]"):
                rollups["reg_set"] += 1
                timeline.append({"t": time.time()-stop_flag["t0"], "type":"reg_set", "detail": line[9:]})
            elif line.startswith("[DNS]"):
                rollups["dns_query"] += 1
                timeline.append({"t": time.time()-stop_flag["t0"], "type":"dns_query", "domain": line[6:]})
    except Exception:
        pass

    proc.wait(timeout=30)
    # stop monitors
    stop_flag["stop"] = True; t.join()
    observer.stop(); observer.join()

    # rollup counts from timeline
    exts=set()
    for ev in timeline:
        if ev["type"] in rollups:
            rollups[ev["type"]] += 1
        if "path" in ev and "." in ev["path"]:
            exts.add(ev["path"].split(".")[-1].lower())
    rollups["unique_exts"] = len(exts)
    rollups["duration_s"] = round(time.time() - stop_flag["t0"], 2)

    # snapshot process metadata
    try:
        p = psutil.Process(pid)
        meta = {"name": p.name(), "pid": pid, "exe": p.exe(), "ppid": p.ppid(), "signed": False}
    except psutil.Error:
        meta = {"name": cmdline[0], "pid": pid, "exe": "", "ppid": None, "signed": False}

    record = {
        "sample_id": sample_id,
        "label": label,
        "target_proc": meta,
        "timeline": timeline,
        "rollups": rollups
    }
    out = RUNS / f"{sample_id}.json"
    out.write_text(json.dumps(record, indent=2))
    print(f"[OK] saved {out}")
    return out

if __name__ == "__main__":
    # Example: run a prototype script
    # python collector.py benign python prototypes.py benign
    label = sys.argv[1]
    cmd = sys.argv[2:]
    run_and_collect(label, cmd)
