#!/usr/bin/env python3
"""Run adversarial attacks against the fraud detection model.

Tests HopSkipJump, SimBA, NES, and ZOO attacks against the deployed
credit card fraud detection model, demonstrating unified AI red teaming
for traditional ML models.

The attacks perturb legitimate transactions to make the model predict
them as fraudulent (or vice versa), measuring the minimum perturbation
needed to flip the prediction.

Usage:
    # Local model (no SageMaker needed):
    python test_adversarial_attack.py --local --attack hopskipjump

    # SageMaker endpoint:
    python test_adversarial_attack.py --endpoint airt-fraud-detection-test --attack hopskipjump

    # All attacks:
    python test_adversarial_attack.py --local --attack all
"""

import argparse
import asyncio
import json
import os
import pickle
import time
from pathlib import Path

import numpy as np


def load_local_model(model_dir: str = "model_artifacts"):
    """Load the locally trained model."""
    with open(os.path.join(model_dir, "model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(model_dir, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    return model, scaler


def load_test_samples(model_dir: str = "model_artifacts"):
    """Load test samples."""
    with open(os.path.join(model_dir, "test_samples.json")) as f:
        return json.load(f)


async def run_attack_local(
    attack_type: str,
    model_dir: str = "model_artifacts",
    n_iterations: int = 100,
    target_class: str = "legit",  # "legit" or "fraud"
):
    """Run an adversarial attack against the local model.

    Uses the SDK's Study framework directly with a custom sampler
    to attack the tabular model. The Image-based SDK attacks expect
    image inputs, so for tabular data we use the underlying
    optimization framework.
    """
    from dreadnode.core.types.image import Image
    from dreadnode.scorers.image import image_distance

    model, scaler = load_local_model(model_dir)
    samples = load_test_samples(model_dir)

    # Pick the sample closest to the decision boundary (easiest to flip)
    if target_class == "fraud":
        # Start with a legit sample, try to make it look fraudulent
        candidates = samples["legit"]
        original_label = "legit"
        target_label = "fraud"
    else:
        # Start with a fraud sample, try to make it look legit
        candidates = samples["fraud"]
        original_label = "fraud"
        target_label = "legit"

    # Find sample closest to 0.5 decision boundary
    best_idx, best_dist = 0, float("inf")
    for i, c in enumerate(candidates):
        x = scaler.transform([c])
        p = model.predict_proba(x)[0][1]  # fraud prob
        dist = abs(p - 0.5)
        if dist < best_dist:
            best_idx, best_dist = i, dist
    sample = np.array(candidates[best_idx], dtype=np.float32)
    print(f"Selected sample [{best_idx}] (closest to boundary, dist={best_dist:.4f})")

    # Normalize to [0, 1] range for the Image wrapper
    sample_min = sample.min()
    sample_max = sample.max()
    sample_range = sample_max - sample_min if sample_max != sample_min else 1.0
    sample_norm = (sample - sample_min) / sample_range

    # Reshape to image format: (height=1, width=n_features)
    n_features = len(sample)
    sample_img = sample_norm.reshape(1, n_features)

    # Wrap as Image
    original = Image(sample_img)

    # Track queries
    query_count = 0

    async def classify(image: Image) -> float:
        """Score function: returns the confidence in the TARGET class.

        We create Studies with direction='maximize' so maximizing this
        means the model is more likely to predict the target class.
        """
        nonlocal query_count
        query_count += 1

        # Extract features from image
        arr = image.to_numpy(dtype=np.float32).flatten()

        # Denormalize back to original scale
        features = arr * sample_range + sample_min

        # Predict
        scaled = scaler.transform([features])
        proba = model.predict_proba(scaled)[0]

        if target_class == "fraud":
            return float(proba[1])  # fraud probability
        else:
            return float(proba[0])  # legit probability

    # Check original prediction
    original_conf = await classify(original)
    print(f"\nOriginal sample ({original_label}):")
    print(f"  Confidence in {original_label}: {original_conf:.4f}")
    print(f"  Goal: minimize this to flip prediction to {target_label}")

    # Import the appropriate attack
    if attack_type == "hopskipjump":
        from dreadnode.airt.image import hopskipjump_attack

        study = hopskipjump_attack(
            source=original,
            objective=classify,
            norm="l2",
            theta=0.01,
            max_iterations=n_iterations,
        )
    elif attack_type == "simba":
        from dreadnode.airt.image import simba_attack

        study = simba_attack(
            original=original,
            objective=classify,
            theta=0.1,
            num_masks=min(500, n_features * 5),
            norm="l2",
            max_iterations=n_iterations,
        )
    elif attack_type == "nes":
        from dreadnode.airt.image import nes_attack

        study = nes_attack(
            original=original,
            objective=classify,
            learning_rate=0.05,
            num_samples=64,
            sigma=0.01,
            max_iterations=n_iterations,
        )
    elif attack_type == "zoo":
        from dreadnode.airt.image import zoo_attack

        study = zoo_attack(
            original=original,
            objective=classify,
            learning_rate=0.01,
            num_samples=min(128, n_features * 4),
            epsilon=0.01,
            max_iterations=n_iterations,
        )
    else:
        raise ValueError(f"Unknown attack: {attack_type}")

    print(f"\nRunning {attack_type} attack ({n_iterations} max iterations)...")
    start_time = time.time()

    result = await study.run()

    elapsed = time.time() - start_time

    print(f"\n{'=' * 60}")
    print(f"RESULTS: {attack_type}")
    print(f"{'=' * 60}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Queries: {query_count}")

    if result.best_trial and result.best_trial.candidate:
        adv = result.best_trial.candidate
        adv_arr = adv.to_numpy(dtype=np.float32).flatten()

        # Check adversarial prediction
        adv_features = adv_arr * sample_range + sample_min
        scaled = scaler.transform([adv_features])
        pred = model.predict(scaled)[0]
        proba = model.predict_proba(scaled)[0]

        adv_label = "fraud" if pred == 1 else "legit"
        adv_conf = await classify(adv)

        # Compute perturbation distance
        perturbation = np.linalg.norm(adv_arr - sample_norm)

        print(f"  Adversarial prediction: {adv_label}")
        print(f"  Original class confidence: {adv_conf:.4f} (was {original_conf:.4f})")
        print(f"  Fraud probability: {proba[1]:.4f}")
        print(f"  L2 perturbation: {perturbation:.6f}")
        print(f"  Attack {'SUCCEEDED' if adv_label == target_label else 'FAILED'}")

        # Show which features changed most
        diff = np.abs(adv_arr - sample_norm)
        top_features = np.argsort(diff)[-5:][::-1]
        feature_names = samples.get("feature_names", [f"F{i}" for i in range(n_features)])
        print(f"\n  Top 5 perturbed features:")
        for idx in top_features:
            name = feature_names[idx] if idx < len(feature_names) else f"F{idx}"
            print(f"    {name}: {sample_norm[idx]:.4f} -> {adv_arr[idx]:.4f} (delta={diff[idx]:.6f})")
    else:
        print(f"  No adversarial example found in {n_iterations} iterations")

    return result


async def run_all_attacks(model_dir: str, n_iterations: int, target_class: str):
    """Run all attack types and compare."""
    attacks = ["hopskipjump", "simba", "nes", "zoo"]
    results = {}

    for attack in attacks:
        print(f"\n{'#' * 60}")
        print(f"# {attack.upper()}")
        print(f"{'#' * 60}")
        try:
            result = await run_attack_local(
                attack, model_dir, n_iterations, target_class
            )
            results[attack] = "OK"
        except Exception as e:
            print(f"  ERROR: {e}")
            results[attack] = f"FAIL: {e}"

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print(f"{'=' * 60}")
    for attack, status in results.items():
        print(f"  {attack:15s}: {status}")


def main():
    parser = argparse.ArgumentParser(description="Adversarial attack on fraud model")
    parser.add_argument(
        "--attack",
        type=str,
        default="hopskipjump",
        choices=["hopskipjump", "simba", "nes", "zoo", "all"],
        help="Attack type",
    )
    parser.add_argument("--local", action="store_true", help="Test locally")
    parser.add_argument("--endpoint", type=str, help="SageMaker endpoint name")
    parser.add_argument("--profile", type=str, default="dreadnode-app-dev")
    parser.add_argument("--region", type=str, default="us-west-2")
    parser.add_argument("--model-dir", type=str, default="model_artifacts")
    parser.add_argument(
        "--iterations", type=int, default=100, help="Max iterations per attack"
    )
    parser.add_argument(
        "--target-class",
        type=str,
        default="fraud",
        choices=["legit", "fraud"],
        help="Class to flip prediction toward",
    )
    args = parser.parse_args()

    if args.attack == "all":
        asyncio.run(run_all_attacks(args.model_dir, args.iterations, args.target_class))
    else:
        asyncio.run(
            run_attack_local(
                args.attack,
                args.model_dir,
                args.iterations,
                args.target_class,
            )
        )


if __name__ == "__main__":
    main()
