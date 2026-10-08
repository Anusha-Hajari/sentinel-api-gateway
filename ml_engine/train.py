import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score

# Import feature extractor from current directory
from features import extract_numerical_features


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(base_dir, "dataset", "payloads.csv")
    model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saved_models")
    os.makedirs(model_dir, exist_ok=True)

    print("=" * 70)
    print("      CSIC 2010 BENCHMARK: MODEL TRAINING & EVALUATION PIPELINE")
    print("=" * 70)

    # 1. Load CSIC 2010 Dataset
    print(f"\n[1/4] Loading CSIC 2010 dataset from: {dataset_path}")
    df = pd.read_csv(dataset_path)
    df["payload"] = df["payload"].fillna("")
    print(f"      Total HTTP requests loaded: {len(df):,}")

    # 2. Train-Test Split (80% Train, 20% Test)
    X = df["payload"]
    y = df["label"].astype(int)
    target_names = ["0: Benign Normal", "1: Anomalous Attack"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"      Training set: {len(X_train):,} requests | Testing set: {len(X_test):,} requests")

    # 3. Supervised Classifier (N-Gram TF-IDF + Random Forest)
    print("\n[2/4] Training Supervised Classifier (TF-IDF N-grams + Random Forest)...")
    t0 = time.time()

    classifier_pipeline = Pipeline([
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

    classifier_pipeline.fit(X_train, y_train)
    train_time = round(time.time() - t0, 2)
    print(f"      Training complete in {train_time} seconds!")

    # 4. Evaluation on 12,213 Unseen Test Requests
    print("\n[3/4] Evaluating on Unseen CSIC 2010 Test Set (12,213 samples):")
    y_pred = classifier_pipeline.predict(X_test)
    y_proba = classifier_pipeline.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    print("-" * 70)
    print(f"      Overall Accuracy : {accuracy * 100:.2f}%")
    print(f"      ROC-AUC Score    : {roc_auc:.4f}\n")
    print(classification_report(y_test, y_pred, target_names=target_names))
    print("      Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("-" * 70)

    # 5. Unsupervised Anomaly Detection (Isolation Forest)
    print("\n[4/4] Training Unsupervised Anomaly Detector (Isolation Forest)...")
    # Train on a representative sample of benign baseline traffic
    benign_sample = X_train[y_train == 0].sample(n=min(5000, sum(y_train == 0)), random_state=42)
    benign_features = np.array([extract_numerical_features(p) for p in benign_sample])

    anomaly_model = IsolationForest(
        n_estimators=100,
        contamination=0.03,
        random_state=42,
        n_jobs=-1
    )
    anomaly_model.fit(benign_features)
    print("      Isolation Forest trained on normal traffic baseline.")

    # 6. Save Model Artifacts
    clf_path = os.path.join(model_dir, "payload_classifier.joblib")
    anom_path = os.path.join(model_dir, "anomaly_detector.joblib")

    joblib.dump(classifier_pipeline, clf_path)
    joblib.dump(anomaly_model, anom_path)

    print("\n" + "=" * 70)
    print("[+] Models successfully trained & serialized:")
    print(f"    - Supervised Model : {clf_path}")
    print(f"    - Anomaly Detector : {anom_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()