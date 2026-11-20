import os
import sys
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
)

BASE_DIR = r"C:\Users\HP\OneDrive\Documents\sentinel-api-gateway"
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "payloads.csv")
OUTPUT_DIR = os.path.join(BASE_DIR, "evaluation_charts")
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 75)
print("  SENTINEL-API GATEWAY: COMPLETE BENCHMARK & EVALUATION SUITE")
print("=" * 75)

# 1. Load Data
print(f"\n[1/5] Loading CSIC 2010 dataset from: {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)
df["payload"] = df["payload"].fillna("")

X = df["payload"]
y = df["label"].astype(int)

print(f"      Total Samples : {len(df):,}")
print(f"      Class 0 (Benign Normal)    : {sum(y == 0):,} requests")
print(f"      Class 1 (Anomalous Attack) : {sum(y == 1):,} requests")

# Stratified 80:20 Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"      Training Set  : {len(X_train):,} samples (80%)")
print(f"      Testing Set   : {len(X_test):,} samples (20%)")

# 2. Train Model Pipeline
print("\n[2/5] Training Random Forest with Character N-Gram TF-IDF...")
t0 = time.time()

pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 4),
        max_features=10000,
        sublinear_tf=True
    )),
    ("rf", RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    ))
])

pipeline.fit(X_train, y_train)
train_duration = round(time.time() - t0, 2)
print(f"      Model successfully trained in {train_duration} seconds!")

# 3. Calculate Predictions & All Metrics
print("\n[3/5] Evaluating on 12,213 Unseen Test Samples...")
y_pred = pipeline.predict(X_test)
y_proba = pipeline.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
fpr, tpr, _ = roc_curve(y_test, y_proba)
roc_auc = auc(fpr, tpr)
prec_curve, rec_curve, _ = precision_recall_curve(y_test, y_proba)
ap_score = average_precision_score(y_test, y_proba)
cm = confusion_matrix(y_test, y_pred)

print("\n" + "=" * 55)
print("             EXACT COMPUTED METRICS")
print("=" * 55)
print(f"  Accuracy           : {acc:.4f}  ({acc*100:.2f}%)")
print(f"  Precision          : {prec:.4f}  ({prec*100:.2f}%)")
print(f"  Recall             : {rec:.4f}  ({rec*100:.2f}%)")
print(f"  F1-Score           : {f1:.4f}  ({f1*100:.2f}%)")
print(f"  ROC-AUC Score      : {roc_auc:.4f}")
print(f"  Average Precision  : {ap_score:.4f}")
print("=" * 55)

print("\nDetailed Confusion Matrix Breakdown:")
print(f"  True Negatives  (Benign correctly allowed) : {cm[0][0]:,}")
print(f"  False Positives (Benign wrongly flagged)   : {cm[0][1]:,}")
print(f"  False Negatives (Attacks missed)           : {cm[1][0]:,}")
print(f"  True Positives  (Attacks correctly blocked): {cm[1][1]:,}")

print("\nFull Classification Report:")
print(classification_report(y_test, y_pred, target_names=["0: Benign", "1: Attack"], digits=4))

# 4. Generate Fresh Figures
print("\n[4/5] Rendering High-Resolution Charts for Paper/Report...")

# Graph 1: Confusion Matrix
plt.figure(figsize=(6, 5), dpi=300)
sns.heatmap(
    cm, annot=True, fmt="d", cmap="Blues", cbar=True,
    xticklabels=["Predicted Benign", "Predicted Attack"],
    yticklabels=["Actual Benign", "Actual Attack"],
    annot_kws={"size": 13, "weight": "bold"}
)
plt.title(f"Confusion Matrix (Accuracy: {acc*100:.2f}%)", fontsize=12, weight="bold", pad=12)
plt.xlabel("Predicted Class", fontsize=10, weight="bold")
plt.ylabel("Ground Truth Class", fontsize=10, weight="bold")
plt.tight_layout()
cm_path = os.path.join(OUTPUT_DIR, "confusion_matrix.png")
plt.savefig(cm_path)
plt.close()
print(f"      [+] Saved: {cm_path}")

# Graph 2: ROC-AUC Curve
plt.figure(figsize=(6, 5), dpi=300)
plt.plot(fpr, tpr, color="#2563eb", lw=2.5, label=f"Random Forest (AUC = {roc_auc:.4f})")
plt.plot([0, 1], [0, 1], color="#9ca3af", lw=1.5, linestyle="--", label="Random Baseline (AUC = 0.50)")
plt.xlabel("False Positive Rate", fontsize=10, weight="bold")
plt.ylabel("True Positive Rate (Recall)", fontsize=10, weight="bold")
plt.title("Receiver Operating Characteristic (ROC) Curve", fontsize=12, weight="bold", pad=12)
plt.legend(loc="lower right", fontsize=10)
plt.grid(True, linestyle=":", alpha=0.6)
plt.tight_layout()
roc_path = os.path.join(OUTPUT_DIR, "roc_curve.png")
plt.savefig(roc_path)
plt.close()
print(f"      [+] Saved: {roc_path}")

# Graph 3: Precision-Recall Curve
plt.figure(figsize=(6, 5), dpi=300)
plt.plot(rec_curve, prec_curve, color="#059669", lw=2.5, label=f"PR Curve (AP = {ap_score:.4f})")
plt.xlabel("Recall", fontsize=10, weight="bold")
plt.ylabel("Precision", fontsize=10, weight="bold")
plt.title("Precision-Recall Curve", fontsize=12, weight="bold", pad=12)
plt.legend(loc="lower left", fontsize=10)
plt.grid(True, linestyle=":", alpha=0.6)
plt.tight_layout()
pr_path = os.path.join(OUTPUT_DIR, "precision_recall_curve.png")
plt.savefig(pr_path)
plt.close()
print(f"      [+] Saved: {pr_path}")

# Graph 4: Evaluation Summary Bar Chart
plt.figure(figsize=(7, 4.5), dpi=300)
metric_names = ["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"]
metric_vals = [acc, prec, rec, f1, roc_auc]
colors = ["#1e40af", "#047857", "#b91c1c", "#7c3aed", "#d97706"]

bars = plt.bar(metric_names, metric_vals, color=colors, width=0.55, edgecolor="#000000", linewidth=0.8)
plt.ylim(0.80, 1.02)
plt.ylabel("Score (0.0 to 1.0)", fontsize=10, weight="bold")
plt.title("SentinelAPI Random Forest Performance Benchmarks", fontsize=12, weight="bold", pad=12)
plt.grid(axis="y", linestyle="--", alpha=0.5)

for bar in bars:
    yval = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2.0, yval + 0.008, f"{yval:.4f}", ha="center", va="bottom", fontsize=10, weight="bold")

plt.tight_layout()
summary_path = os.path.join(OUTPUT_DIR, "evaluation_summary_barchart.png")
plt.savefig(summary_path)
plt.close()
print(f"      [+] Saved: {summary_path}")

print("\n[5/5] ALL BENCHMARKS & CHARTS SUCCESSFULLY COMPUTED AND SAVED!")
