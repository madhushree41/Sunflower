import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
from pathlib import Path
import numpy as np

CSV_FILE = Path("data/dataset1.csv")
MODEL_FILE = Path("model_raw.bin")

LABELS = {"benign":0, "wiper":1, "ransom":2, "beacon":3, "persist":4}

df = pd.read_csv(CSV_FILE)

# Map string labels to integers
df["label"] = df["label"].map(LABELS)

feats = [
    "file_create", "file_delete", "file_modify",
    "folder_create", "folder_delete",
    "reg_set", "reg_delete",
    "dns_query", "net_connect", "proc_spawn",
    "cpu_max", "duration_s", "unique_exts"
]

X, y = df[feats], df["label"]

# log-transform skewed features
for col in ["duration_s", "cpu_max"]:
    X[col] = np.log1p(X[col])

X_train, X_test, y_train, y_test = train_test_split(
    X, y, stratify=y, test_size=0.3, random_state=42
)

model = XGBClassifier(
    n_estimators=500,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    reg_lambda=1.0,
    tree_method="hist",
    eval_metric="mlogloss"
)
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

print(classification_report(y_test, y_pred, target_names=LABELS.keys()))

joblib.dump({"model": model, "features": feats, "labels": LABELS}, MODEL_FILE.open("wb"))
print(f"[OK] saved model to {MODEL_FILE}")
