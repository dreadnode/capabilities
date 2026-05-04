#!/usr/bin/env python3
"""Deploy the fraud detection model to SageMaker using the sagemaker Python SDK."""

import argparse
import json
import os
from pathlib import Path

import boto3
import sagemaker
from sagemaker.sklearn.model import SKLearnModel


def get_or_create_role(iam_client, role_name="dreadnode-sagemaker-test-role"):
    """Get or create a SageMaker execution role."""
    try:
        role = iam_client.get_role(RoleName=role_name)
        return role["Role"]["Arn"]
    except iam_client.exceptions.NoSuchEntityException:
        pass

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="SageMaker execution role for AIRT testing",
    )
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    print(f"Created IAM role: {role['Role']['Arn']}")
    import time
    time.sleep(10)
    return role["Role"]["Arn"]


def main():
    parser = argparse.ArgumentParser(description="Deploy fraud model to SageMaker")
    parser.add_argument("--profile", type=str, default="dreadnode-app-dev")
    parser.add_argument("--region", type=str, default="us-west-2")
    parser.add_argument("--model-dir", type=str, default="model_artifacts")
    parser.add_argument("--endpoint-name", type=str, default="airt-fraud-detection-test")
    parser.add_argument("--instance-type", type=str, default="ml.t2.medium")
    args = parser.parse_args()

    boto_session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = boto_session.client("sts").get_caller_identity()["Account"]
    print(f"AWS Account: {account_id}, Region: {args.region}")

    # Get role
    iam = boto_session.client("iam")
    role_arn = get_or_create_role(iam)
    print(f"Using role: {role_arn}")

    # Create sagemaker session
    sm_session = sagemaker.Session(boto_session=boto_session)

    # Write inference script
    code_dir = Path("/tmp/sagemaker_fraud_code")
    code_dir.mkdir(parents=True, exist_ok=True)

    inference_code = '''
import json
import os
import pickle

import numpy as np


def model_fn(model_dir):
    """Load model and scaler from the model directory."""
    with open(os.path.join(model_dir, "model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(model_dir, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    return {"model": model, "scaler": scaler}


def input_fn(request_body, content_type="application/json"):
    """Parse input data from the request."""
    if content_type == "application/json":
        data = json.loads(request_body)
        if "instances" in data:
            features = [inst["features"] for inst in data["instances"]]
        elif "features" in data:
            features = [data["features"]]
        elif isinstance(data, list):
            features = data
        else:
            raise ValueError(f"Unsupported JSON format: {list(data.keys())}")
        return np.array(features, dtype=np.float64)
    raise ValueError(f"Unsupported content type: {content_type}")


def predict_fn(input_data, model_dict):
    """Run prediction."""
    scaler = model_dict["scaler"]
    model = model_dict["model"]

    scaled = scaler.transform(input_data)
    predictions = model.predict(scaled)
    probabilities = model.predict_proba(scaled)

    results = []
    for pred, proba in zip(predictions, probabilities):
        results.append({
            "class": int(pred),
            "label": "fraud" if pred == 1 else "legit",
            "confidence": float(proba[int(pred)]),
            "fraud_probability": float(proba[1]),
        })
    return results


def output_fn(prediction, accept="application/json"):
    """Format the prediction output."""
    return json.dumps({"predictions": prediction}), accept
'''
    (code_dir / "inference.py").write_text(inference_code)
    print(f"Inference script written to {code_dir / 'inference.py'}")

    # Create SKLearnModel using the SDK
    model = SKLearnModel(
        model_data=os.path.join(args.model_dir, "model.tar.gz"),
        role=role_arn,
        entry_point=str(code_dir / "inference.py"),
        framework_version="1.2-1",
        sagemaker_session=sm_session,
        name=f"{args.endpoint_name}-model",
    )

    # First, we need to create model.tar.gz with just the pkl files
    import tarfile
    tar_path = os.path.join(args.model_dir, "model.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(os.path.join(args.model_dir, "model.pkl"), arcname="model.pkl")
        tar.add(os.path.join(args.model_dir, "scaler.pkl"), arcname="scaler.pkl")
    print(f"Model tar.gz created: {tar_path}")

    # Upload model data to S3
    bucket = sm_session.default_bucket()
    s3_key = f"airt-test/fraud-model/model.tar.gz"
    s3_uri = sm_session.upload_data(
        path=tar_path,
        bucket=bucket,
        key_prefix="airt-test/fraud-model",
    )
    print(f"Model uploaded to: {s3_uri}")

    # Create model with S3 data
    model = SKLearnModel(
        model_data=s3_uri,
        role=role_arn,
        entry_point=str(code_dir / "inference.py"),
        framework_version="1.2-1",
        sagemaker_session=sm_session,
    )

    print(f"\nDeploying to endpoint: {args.endpoint_name}")
    predictor = model.deploy(
        initial_instance_count=1,
        instance_type=args.instance_type,
        endpoint_name=args.endpoint_name,
    )

    print(f"\nEndpoint ready: {args.endpoint_name}")
    print(f"\nTest with:")
    print(f"  python test_local.py --endpoint {args.endpoint_name} --profile {args.profile}")

    # Save endpoint info
    info = {
        "endpoint_name": args.endpoint_name,
        "region": args.region,
        "profile": args.profile,
        "account_id": account_id,
        "model_data_url": s3_uri,
    }
    with open("endpoint_info.json", "w") as f:
        json.dump(info, f, indent=2)
    print(f"Endpoint info saved to endpoint_info.json")


if __name__ == "__main__":
    main()
