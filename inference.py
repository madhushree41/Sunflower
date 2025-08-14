import pandas as pd
import numpy as np
import joblib

data = joblib.load("model_raw.bin")
model = data["model"]
feats = data["features"]
LABELS = data["labels"]
LABELS_INV = {v: k for k, v in LABELS.items()}


input_dict =input_dict = {
    "sample_id": "85b120a7-0fb9-42c1-a2c8-8857382edd65",
    "file_create": 0,
    "file_delete": 0,
    "file_modify": 2,
    "folder_create": 0,
    "folder_delete": 0,
    "reg_set": 0,
    "reg_delete": 0,
    "dns_query": 6,
    "net_connect": 0,
    "proc_spawn": 0,
    "cpu_max": 15.2,
    "duration_s": 2.21,
    "unique_exts": 1
}

df_input = pd.DataFrame([input_dict])

for col in ["duration_s", "cpu_max"]:
    df_input[col] = np.log1p(df_input[col])
X_input = df_input[feats]

y_pred_int = model.predict(X_input)
y_pred_name = [LABELS_INV[i] for i in y_pred_int]

print(f"Predicted label: {y_pred_name[0]}")
