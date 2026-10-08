import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    confusion_matrix, roc_curve, auc, 
    precision_recall_curve, average_precision_score
)

from features import calculate_entropy


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base_dir, "dataset", "payloads.csv")
    model_path = os.path.join(base_dir, "ml_engine", "saved_models", "payload_classifier.joblib")
    output_dir = os.path.join(base_dir, "evaluation_charts")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 70)
    print(" GENERATING FULL ACADEMIC SUITE OF 5 ML EVALUATION CHARTS")
    print("=" * 70)

    # 1. Load Data
    print("[1/5] Ingesting CSIC dataset and model...")
    df = pd.read_csv(dataset_path)
    df["payload"] = df["payload"].fillna("")
    X = df["payload"]
    y = df["label"].astype(int)

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    model = joblib.load(model_path)
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    # ------------------------------------------------------------------
    # GRAPH 1: CONFUSION MATRIX HEATMAP
    # ------------------------------------------------------------------
    print("[2/5] Plotting 1. Confusion Matrix...")
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6.5, 5.5), dpi=300)
    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Benign (Normal)", "Anomalous (Attack)"],
        yticklabels=["Benign (Normal)", "Anomalous (Attack)"],
        annot_kws={"size": 13, "weight": "bold"}
    )
    plt.title("CSIC 2010 Benchmark: Confusion Matrix", fontsize=12, weight="bold", pad=12)
    plt.xlabel("Predicted Label", fontsize=10, weight="bold")
    plt.ylabel("Actual True Label", fontsize=10, weight="bold")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "confusion_matrix.png"))
    plt.close()

    # ------------------------------------------------------------------
    # GRAPH 2: ROC-AUC CURVE
    # ------------------------------------------------------------------
    print("[3/5] Plotting 2. ROC-AUC Curve...")
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(6.5, 5.5), dpi=300)
    plt.plot(fpr, tpr, color="#1d4ed8", lw=2.5, label=f"Random Forest (AUC = {roc_auc:.4f})")
    plt.plot([0, 1], [0, 1], color="#9ca3af", lw=1.5, linestyle="--", label="Random Baseline (AUC = 0.50)")
    plt.xlabel("False Positive Rate", fontsize=10, weight="bold")
    plt.ylabel("True Positive Rate (Recall)", fontsize=10, weight="bold")
    plt.title("Receiver Operating Characteristic (ROC) Curve", fontsize=12, weight="bold", pad=12)
    plt.legend(loc="lower right", fontsize=10)
    plt.grid(True, linestyle=":", alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "roc_curve.png"))
    plt.close()

    # ------------------------------------------------------------------
    # GRAPH 3: PRECISION-RECALL CURVE
    # ------------------------------------------------------------------
    print("[4/5] Plotting 3. Precision-Recall Curve...")
    precision, recall, _ = precision_recall_curve(y_test, y_proba)
    ap_score = average_precision_score(y_test, y_proba)
    plt.figure(figsize=(6.5, 5.5), dpi=300)
    plt.plot(recall, precision, color="#10b981", lw=2.5, label=f"Precision-Recall (AP = {ap_score:.4f})")
    plt.xlabel("Recall", fontsize=10, weight="bold")
    plt.ylabel("Precision", fontsize=10, weight="bold")
    plt.title("Precision-Recall Curve (Cybersecurity Benchmark)", fontsize=12, weight="bold", pad=12)
    plt.legend(loc="lower left", fontsize=10)
    plt.grid(True, linestyle=":", alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "precision_recall_curve.png"))
    plt.close()

    # ------------------------------------------------------------------
    # GRAPH 4: SHANNON ENTROPY DISTRIBUTION (Benign vs Attack)
    # ------------------------------------------------------------------
    print("[5/5] Plotting 4. Shannon Entropy Distribution...")
    sample_df = df.sample(n=min(5000, len(df)), random_state=42).copy()
    sample_df["entropy"] = sample_df["payload"].apply(calculate_entropy)

    plt.figure(figsize=(7, 5), dpi=300)
    sns.kdeplot(
        data=sample_df[sample_df["label"] == 0]["entropy"],
        color="#10b981", fill=True, label="Benign Traffic (Normal)", alpha=0.4, lw=2
    )
    sns.kdeplot(
        data=sample_df[sample_df["label"] == 1]["entropy"],
        color="#ef4444", fill=True, label="Anomalous / Attack Traffic", alpha=0.4, lw=2
    )
    plt.title("Information Theory: Shannon Entropy Density Comparison", fontsize=12, weight="bold", pad=12)
    plt.xlabel("Shannon Entropy Score ($H$)", fontsize=10, weight="bold")
    plt.ylabel("Density", fontsize=10, weight="bold")
    plt.legend(loc="upper right", fontsize=10)
    plt.grid(True, linestyle=":", alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "entropy_distribution.png"))
    plt.close()

    # ------------------------------------------------------------------
    # GRAPH 5: TOP 15 INFORMATIVE N-GRAM FEATURES
    # ------------------------------------------------------------------
    print("[+] Plotting 5. Top 15 Informative Attack N-Grams...")
    vectorizer = model.named_steps["tfidf"]
    rf = model.named_steps["rf"]
    feature_names = np.array(vectorizer.get_feature_names_out())
    importances = rf.feature_importances_

    # Get top 15 indices
    top_indices = np.argsort(importances)[-15:]
    top_features = feature_names[top_indices]
    top_weights = importances[top_indices]

    plt.figure(figsize=(8, 5.5), dpi=300)
    plt.barh(range(len(top_features)), top_weights, color="#6366f1", edgecolor="#312e81")
    plt.yticks(range(len(top_features)), [f"'{f}'" for f in top_features], fontsize=10, family="monospace")
    plt.xlabel("Relative Feature Importance (Gini Impurity)", fontsize=10, weight="bold")
    plt.title("Model Explainability: Top 15 Informative Character N-Grams", fontsize=12, weight="bold", pad=12)
    plt.grid(True, axis="x", linestyle=":", alpha=0.6)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "top_attack_tokens.png"))
    plt.close()

    print("\n" + "=" * 70)
    print(f"[+] COMPLETE! All 5 graphs generated in: {output_dir}")
    print("    1. confusion_matrix.png")
    print("    2. roc_curve.png")
    print("    3. precision_recall_curve.png")
    print("    4. entropy_distribution.png")
    print("    5. top_attack_tokens.png")
    print("=" * 70)


if __name__ == "__main__":
    main()