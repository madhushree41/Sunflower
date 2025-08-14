import json
import csv
from pathlib import Path

# Paths
json_dir = Path("data/runs")  
csv_file = Path("data/dataset1.csv") 


fieldnames = [
    "sample_id", "label",
    "file_create", "file_delete", "file_modify",
    "folder_create", "folder_delete",
    "reg_set", "reg_delete",
    "dns_query", "net_connect", "proc_spawn",
    "cpu_max", "duration_s", "unique_exts"
]

rows = []

for json_path in json_dir.glob("*.json"):
    with open(json_path, "r") as f:
        data = json.load(f)
    
    row = {
        "sample_id": data.get("sample_id", ""),
        "label": data.get("label", "")
    }
    
    rollups = data.get("rollups", {})
    for col in fieldnames[2:]:  
        row[col] = rollups.get(col, 0)
    
    rows.append(row)

with open(csv_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

print(f"CSV created at {csv_file} with {len(rows)} samples.")
