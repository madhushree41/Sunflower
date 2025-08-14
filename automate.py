import subprocess
import os
import uuid
import csv
import json
from pathlib import Path

runs_dir = Path("data/new_runs")
csv_file = Path("data/dataset.csv")
num_samples_per_class = 1  
classes = {
    "benign": "prototypes.py",
    "ransom": "prototypes.py",
    "wiper": "prototypes.py",
    "beacon": "prototypes.py",
    "persist": "prototypes.py"
}

runs_dir.mkdir(parents=True, exist_ok=True)

all_data = []

for label, script in classes.items():
    print(f"Generating samples for class: {label}")
    for i in range(num_samples_per_class):
        sample_id = str(uuid.uuid4())

        result = subprocess.run([
            "python", "collector.py",
            label, "python", script, label
        ], capture_output=True, text=True)
        
        for line in result.stdout.splitlines():
            if line.startswith("[OK] saved"):
                output_file = Path(line.split()[2])
                break
        else:
            print(f"[ERROR] No output file found for {label} run {i}")
            continue

        with open(output_file) as f:
            data = json.load(f)
            row = {
                "sample_id": data.get("sample_id", sample_id),
                "label": label,
                **data.get("rollups", {})
            }
            all_data.append(row)


fieldnames = ["sample_id","label","file_create","file_delete","file_modify","folder_create",
              "folder_delete","reg_set","reg_delete","dns_query","net_connect","proc_spawn",
              "cpu_max","duration_s","unique_exts"]

with open(csv_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_data)

print(f"Dataset CSV created at {csv_file} with {len(all_data)} samples.")
