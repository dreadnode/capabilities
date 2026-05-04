#!/usr/bin/env python3
"""Train a credit card fraud detection model for adversarial attack testing.

Downloads the Kaggle credit card fraud dataset (or generates synthetic data
as fallback), trains a RandomForest classifier, and saves the model + scaler
for SageMaker deployment.

Usage:
    # With real Kaggle data (download creditcard.csv first):
    python train_fraud_model.py --data creditcard.csv

    # With synthetic data (no download needed):
    python train_fraud_model.py --synthetic
"""

import argparse
import json
import os
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


def load_kaggle_data(csv_path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load the real Kaggle credit card fraud dataset."""
    import pandas as pd

    df = pd.read_csv(csv_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Fraud ratio: {df['Class'].mean():.4f} ({df['Class'].sum()} / {len(df)})")

    X = df.drop("Class", axis=1).values
    y = df["Class"].values
    return X, y


def generate_synthetic_data(n_samples: int = 10000) -> tuple[np.ndarray, np.ndarray]:
    """Generate synthetic credit card fraud data for testing.

    Creates two well-separated clusters so the model can learn
    a meaningful decision boundary for adversarial testing.
    Uses 20% fraud rate for balanced training.
    """
    rng = np.random.RandomState(42)
    n_fraud = max(int(n_samples * 0.2), 100)
    n_legit = n_samples - n_fraud

    # Legitimate transactions: centered near origin
    X_legit = rng.randn(n_legit, 30) * 1.0

    # Fraudulent transactions: slightly shifted — intentionally overlapping
    # so the model has a non-trivial decision boundary (realistic for adversarial testing)
    shift = rng.uniform(0.3, 0.8, size=30)
    X_fraud = rng.randn(n_fraud, 30) * 1.1 + shift

    X = np.vstack([X_legit, X_fraud])
    y = np.concatenate([np.zeros(n_legit), np.ones(n_fraud)])

    # Shuffle
    idx = rng.permutation(len(y))
    return X[idx], y[idx]


def main():
    parser = argparse.ArgumentParser(description="Train fraud detection model")
    parser.add_argument("--data", type=str, help="Path to creditcard.csv from Kaggle")
    parser.add_argument("--synthetic", action="store_true", help="Use synthetic data")
    parser.add_argument(
        "--output-dir",
        type=str,
        default="model_artifacts",
        help="Output directory for model files",
    )
    args = parser.parse_args()

    if args.data:
        X, y = load_kaggle_data(args.data)
    elif args.synthetic:
        print("Generating synthetic credit card fraud data...")
        X, y = generate_synthetic_data(n_samples=50000)
        print(f"Generated {len(X)} samples, {int(y.sum())} fraudulent")
    else:
        # Try to find creditcard.csv in common locations
        candidates = [
            "creditcard.csv",
            "data/creditcard.csv",
            os.path.expanduser("~/Downloads/creditcard.csv"),
        ]
        found = None
        for c in candidates:
            if os.path.exists(c):
                found = c
                break
        if found:
            print(f"Found dataset at {found}")
            X, y = load_kaggle_data(found)
        else:
            print("No dataset found. Using synthetic data.")
            print("For real data: download from https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud")
            X, y = generate_synthetic_data(n_samples=50000)
            print(f"Generated {len(X)} samples, {int(y.sum())} fraudulent")

    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train RandomForest
    print("\nTraining RandomForest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)[:, 1]

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Fraud"]))
    print(f"ROC AUC: {roc_auc_score(y_test, y_proba):.4f}")

    # Save model + scaler
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "model.pkl"
    scaler_path = output_dir / "scaler.pkl"

    with open(model_path, "wb") as f:
        pickle.dump(model, f)
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)

    # Save test samples for attack testing
    # Pick a few legit and fraud samples
    legit_idx = np.where(y_test == 0)[0][:5]
    fraud_idx = np.where(y_test == 1)[0][:5]

    test_samples = {
        "legit": X_test[legit_idx].tolist(),
        "fraud": X_test[fraud_idx].tolist(),
        "legit_scaled": X_test_scaled[legit_idx].tolist(),
        "fraud_scaled": X_test_scaled[fraud_idx].tolist(),
        "feature_names": [
            "Time",
            *[f"V{i}" for i in range(1, 29)],
            "Amount",
        ],
        "n_features": X_test.shape[1],
    }
    with open(output_dir / "test_samples.json", "w") as f:
        json.dump(test_samples, f, indent=2)

    print(f"\nModel saved to {model_path}")
    print(f"Scaler saved to {scaler_path}")
    print(f"Test samples saved to {output_dir / 'test_samples.json'}")
    print(f"\nNext: deploy with deploy_sagemaker.py or test locally with test_local.py")


if __name__ == "__main__":
    main()
