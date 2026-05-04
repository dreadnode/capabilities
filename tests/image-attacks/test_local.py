#!/usr/bin/env python3
"""Test the fraud detection model locally or against a SageMaker endpoint.

Usage:
    # Local test (no SageMaker needed):
    python test_local.py --local

    # SageMaker endpoint test:
    python test_local.py --endpoint airt-fraud-detection-test --profile dreadnode-app-dev
"""

import argparse
import json
import os
import pickle
from pathlib import Path

import numpy as np


def test_local(model_dir: str = "model_artifacts"):
    """Test the model locally."""
    with open(os.path.join(model_dir, "model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(model_dir, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    with open(os.path.join(model_dir, "test_samples.json")) as f:
        samples = json.load(f)

    print("Testing locally...\n")

    for label in ["legit", "fraud"]:
        raw = np.array(samples[label])
        scaled = scaler.transform(raw)
        preds = model.predict(scaled)
        probas = model.predict_proba(scaled)

        print(f"{label.upper()} samples ({len(raw)}):")
        for i, (pred, proba) in enumerate(zip(preds, probas)):
            print(
                f"  [{i}] predicted={'fraud' if pred else 'legit'} "
                f"(fraud_prob={proba[1]:.4f}, legit_prob={proba[0]:.4f})"
            )
        print()

    # Test with a perturbed sample
    print("Perturbation test:")
    legit_sample = np.array(samples["legit"][0])
    print(f"  Original: {model.predict(scaler.transform([legit_sample]))[0]} "
          f"(fraud_prob={model.predict_proba(scaler.transform([legit_sample]))[0][1]:.4f})")

    # Add noise
    rng = np.random.RandomState(42)
    for noise_level in [0.1, 0.5, 1.0, 2.0, 5.0]:
        perturbed = legit_sample + rng.randn(len(legit_sample)) * noise_level
        scaled = scaler.transform([perturbed])
        pred = model.predict(scaled)[0]
        proba = model.predict_proba(scaled)[0]
        print(
            f"  Noise={noise_level:.1f}: predicted={'fraud' if pred else 'legit'} "
            f"(fraud_prob={proba[1]:.4f})"
        )


def test_sagemaker(endpoint_name: str, profile: str, region: str = "us-west-2"):
    """Test the SageMaker endpoint."""
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    runtime = session.client("sagemaker-runtime")

    with open("model_artifacts/test_samples.json") as f:
        samples = json.load(f)

    print(f"Testing SageMaker endpoint: {endpoint_name}\n")

    for label in ["legit", "fraud"]:
        raw = samples[label]
        payload = {"instances": [{"features": row} for row in raw]}

        response = runtime.invoke_endpoint(
            EndpointName=endpoint_name,
            ContentType="application/json",
            Body=json.dumps(payload),
        )
        result = json.loads(response["Body"].read().decode())

        print(f"{label.upper()} samples ({len(raw)}):")
        for i, pred in enumerate(result["predictions"]):
            print(
                f"  [{i}] predicted={pred['label']} "
                f"(confidence={pred['confidence']:.4f}, "
                f"fraud_prob={pred['fraud_probability']:.4f})"
            )
        print()


def main():
    parser = argparse.ArgumentParser(description="Test fraud detection model")
    parser.add_argument("--local", action="store_true", help="Test locally")
    parser.add_argument("--endpoint", type=str, help="SageMaker endpoint name")
    parser.add_argument("--profile", type=str, default="dreadnode-app-dev")
    parser.add_argument("--region", type=str, default="us-west-2")
    parser.add_argument("--model-dir", type=str, default="model_artifacts")
    args = parser.parse_args()

    if args.local or not args.endpoint:
        test_local(args.model_dir)
    if args.endpoint:
        test_sagemaker(args.endpoint, args.profile, args.region)


if __name__ == "__main__":
    main()
