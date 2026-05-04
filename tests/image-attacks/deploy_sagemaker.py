#!/usr/bin/env python3
"""Deploy the fraud detection model to AWS SageMaker.

Creates a SageMaker endpoint using the SKLearn container that accepts
JSON requests with feature arrays and returns fraud probabilities.

Prerequisites:
    - AWS SSO login: aws sso login --profile dreadnode-app-dev
    - Model artifacts: run train_fraud_model.py first
    - SageMaker execution role (auto-created if needed)

Usage:
    python deploy_sagemaker.py --profile dreadnode-app-dev

The endpoint accepts:
    POST /invocations
    Content-Type: application/json
    {"instances": [{"features": [0.1, 0.2, ...]}]}

    Response: {"predictions": [{"class": 0, "confidence": 0.95}]}
"""

import argparse
import json
import os
import shutil
import tarfile
from pathlib import Path

import boto3


def create_model_tar(model_dir: str, output_path: str = "model.tar.gz"):
    """Package model artifacts into a tar.gz for SageMaker."""
    with tarfile.open(output_path, "w:gz") as tar:
        tar.add(os.path.join(model_dir, "model.pkl"), arcname="model.pkl")
        tar.add(os.path.join(model_dir, "scaler.pkl"), arcname="scaler.pkl")

        # Create inference script
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
        # Write inference script and setup.py to a temp dir and add to tar
        code_dir = Path("/tmp/sagemaker_code")
        code_dir.mkdir(parents=True, exist_ok=True)
        (code_dir / "inference.py").write_text(inference_code)
        (code_dir / "setup.py").write_text(
            "from setuptools import setup\n"
            "setup(name='inference', version='1.0', py_modules=['inference'])\n"
        )
        tar.add(str(code_dir / "inference.py"), arcname="code/inference.py")
        tar.add(str(code_dir / "setup.py"), arcname="code/setup.py")

    print(f"Model package created: {output_path}")
    return output_path


def get_or_create_role(iam_client, role_name: str = "dreadnode-sagemaker-test-role") -> str:
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
    # Wait for role propagation
    import time
    time.sleep(10)
    return role["Role"]["Arn"]


def main():
    parser = argparse.ArgumentParser(description="Deploy fraud model to SageMaker")
    parser.add_argument(
        "--profile", type=str, default="dreadnode-app-dev", help="AWS profile"
    )
    parser.add_argument(
        "--region", type=str, default="us-west-2", help="AWS region"
    )
    parser.add_argument(
        "--model-dir",
        type=str,
        default="model_artifacts",
        help="Directory with model.pkl and scaler.pkl",
    )
    parser.add_argument(
        "--endpoint-name",
        type=str,
        default="airt-fraud-detection-test",
        help="SageMaker endpoint name",
    )
    parser.add_argument(
        "--instance-type",
        type=str,
        default="ml.t2.medium",
        help="SageMaker instance type",
    )
    parser.add_argument(
        "--bucket",
        type=str,
        default="",
        help="S3 bucket for model artifacts (auto-created if empty)",
    )
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    print(f"AWS Account: {account_id}, Region: {args.region}")

    # Package model
    tar_path = create_model_tar(args.model_dir)

    # Upload to S3
    bucket = args.bucket or f"dreadnode-sagemaker-test-{account_id}-{args.region}"
    s3 = session.client("s3")
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:
        print(f"Creating S3 bucket: {bucket}")
        if args.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": args.region},
            )

    s3_key = f"airt-test/fraud-model/model.tar.gz"
    s3.upload_file(tar_path, bucket, s3_key)
    model_data_url = f"s3://{bucket}/{s3_key}"
    print(f"Model uploaded: {model_data_url}")

    # Get/create IAM role
    iam = session.client("iam")
    role_arn = get_or_create_role(iam)

    # Create SageMaker model
    sm = session.client("sagemaker")

    # Use the SKLearn container
    sklearn_image = (
        f"246618743249.dkr.ecr.{args.region}.amazonaws.com"
        f"/sagemaker-scikit-learn:1.2-1-cpu-py3"
    )

    model_name = f"{args.endpoint_name}-model"
    try:
        sm.delete_model(ModelName=model_name)
    except Exception:
        pass

    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={
            "Image": sklearn_image,
            "ModelDataUrl": model_data_url,
            "Environment": {
                "SAGEMAKER_PROGRAM": "inference.py",
            },
        },
        ExecutionRoleArn=role_arn,
    )
    print(f"SageMaker model created: {model_name}")

    # Create endpoint config
    config_name = f"{args.endpoint_name}-config"
    try:
        sm.delete_endpoint_config(EndpointConfigName=config_name)
    except Exception:
        pass

    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "default",
                "ModelName": model_name,
                "InstanceType": args.instance_type,
                "InitialInstanceCount": 1,
            }
        ],
    )
    print(f"Endpoint config created: {config_name}")

    # Create or update endpoint
    try:
        sm.describe_endpoint(EndpointName=args.endpoint_name)
        print(f"Updating existing endpoint: {args.endpoint_name}")
        sm.update_endpoint(
            EndpointName=args.endpoint_name, EndpointConfigName=config_name
        )
    except sm.exceptions.ClientError:
        print(f"Creating endpoint: {args.endpoint_name}")
        sm.create_endpoint(
            EndpointName=args.endpoint_name, EndpointConfigName=config_name
        )

    # Wait for endpoint
    print("Waiting for endpoint to be InService...")
    waiter = sm.get_waiter("endpoint_in_service")
    waiter.wait(
        EndpointName=args.endpoint_name,
        WaiterConfig={"Delay": 30, "MaxAttempts": 40},
    )

    endpoint_url = (
        f"https://runtime.sagemaker.{args.region}.amazonaws.com"
        f"/endpoints/{args.endpoint_name}/invocations"
    )
    print(f"\nEndpoint ready: {args.endpoint_name}")
    print(f"URL: {endpoint_url}")
    print(f"\nTest with:")
    print(f'  python test_local.py --endpoint {args.endpoint_name} --profile {args.profile}')

    # Save endpoint info
    info = {
        "endpoint_name": args.endpoint_name,
        "endpoint_url": endpoint_url,
        "region": args.region,
        "profile": args.profile,
        "account_id": account_id,
        "model_data_url": model_data_url,
    }
    with open("endpoint_info.json", "w") as f:
        json.dump(info, f, indent=2)
    print(f"\nEndpoint info saved to endpoint_info.json")


if __name__ == "__main__":
    main()
