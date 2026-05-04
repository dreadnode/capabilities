#!/usr/bin/env python3
"""Deploy the fraud detection model as an AWS Lambda function with a public URL.

Much simpler than SageMaker — just a Lambda function with the model embedded.

Usage:
    python deploy_lambda.py --profile dreadnode-app-dev
"""

import argparse
import io
import json
import os
import pickle
import zipfile

import boto3
import numpy as np


def create_lambda_zip(model_dir: str = "model_artifacts") -> bytes:
    """Create a Lambda deployment zip with model and handler."""

    # Load model and scaler to embed as JSON-serializable data
    with open(os.path.join(model_dir, "model.pkl"), "rb") as f:
        model_bytes = f.read()
    with open(os.path.join(model_dir, "scaler.pkl"), "rb") as f:
        scaler_bytes = f.read()

    handler_code = '''
import json
import os
import pickle
import base64
import io

# Load model and scaler from embedded data
_MODEL_B64 = os.environ.get("MODEL_DATA", "")
_SCALER_B64 = os.environ.get("SCALER_DATA", "")

_model = None
_scaler = None


def _load():
    global _model, _scaler
    if _model is None:
        _model = pickle.loads(base64.b64decode(_MODEL_B64))
        _scaler = pickle.loads(base64.b64decode(_SCALER_B64))


def handler(event, context):
    """Lambda handler for fraud detection."""
    _load()

    # Parse body
    if isinstance(event.get("body"), str):
        body = json.loads(event["body"])
    elif isinstance(event.get("body"), dict):
        body = event["body"]
    else:
        body = event

    # Extract features
    if "instances" in body:
        features = [inst["features"] for inst in body["instances"]]
    elif "features" in body:
        features = [body["features"]]
    elif isinstance(body, list):
        features = body
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Unsupported format: {list(body.keys())}"}),
        }

    import numpy as np
    X = np.array(features, dtype=np.float64)
    scaled = _scaler.transform(X)
    predictions = _model.predict(scaled)
    probabilities = _model.predict_proba(scaled)

    results = []
    for pred, proba in zip(predictions, probabilities):
        results.append({
            "class": int(pred),
            "label": "fraud" if pred == 1 else "legit",
            "confidence": float(proba[int(pred)]),
            "fraud_probability": float(proba[1]),
        })

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"predictions": results}),
    }
'''

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue(), model_bytes, scaler_bytes


def get_or_create_role(iam_client, role_name="dreadnode-lambda-fraud-role"):
    """Get or create a Lambda execution role."""
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
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="Lambda execution role for AIRT fraud detection test",
    )
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    print(f"Created IAM role: {role['Role']['Arn']}")
    import time
    time.sleep(10)
    return role["Role"]["Arn"]


def main():
    parser = argparse.ArgumentParser(description="Deploy fraud model as Lambda")
    parser.add_argument("--profile", type=str, default="dreadnode-app-dev")
    parser.add_argument("--region", type=str, default="us-west-2")
    parser.add_argument("--model-dir", type=str, default="model_artifacts")
    parser.add_argument("--function-name", type=str, default="airt-fraud-detection-test")
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    account_id = session.client("sts").get_caller_identity()["Account"]
    print(f"AWS Account: {account_id}, Region: {args.region}")

    # Get role
    iam = session.client("iam")
    role_arn = get_or_create_role(iam)

    # Create deployment package
    import base64
    zip_bytes, model_bytes, scaler_bytes = create_lambda_zip(args.model_dir)
    model_b64 = base64.b64encode(model_bytes).decode()
    scaler_b64 = base64.b64encode(scaler_bytes).decode()

    # Check if env vars are too large (Lambda limit is 4KB for all env vars)
    total_env_size = len(model_b64) + len(scaler_b64)
    print(f"Model+scaler base64 size: {total_env_size:,} bytes")

    if total_env_size > 3500:
        # Too large for env vars — embed in the zip directly
        print("Model too large for env vars, embedding in zip...")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Modified handler that loads from files
            handler_code = '''
import json
import os
import pickle

_model = None
_scaler = None


def _load():
    global _model, _scaler
    if _model is None:
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "model.pkl"), "rb") as f:
            _model = pickle.load(f)
        with open(os.path.join(base, "scaler.pkl"), "rb") as f:
            _scaler = pickle.load(f)


def handler(event, context):
    """Lambda handler for fraud detection."""
    _load()

    # Parse body
    if isinstance(event.get("body"), str):
        body = json.loads(event["body"])
    elif isinstance(event.get("body"), dict):
        body = event["body"]
    else:
        body = event

    # Extract features
    if "instances" in body:
        features = [inst["features"] for inst in body["instances"]]
    elif "features" in body:
        features = [body["features"]]
    elif isinstance(body, list):
        features = body
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Unsupported format: {list(body.keys())}"}),
        }

    import numpy as np
    X = np.array(features, dtype=np.float64)
    scaled = _scaler.transform(X)
    predictions = _model.predict(scaled)
    probabilities = _model.predict_proba(scaled)

    results = []
    for pred, proba in zip(predictions, probabilities):
        results.append({
            "class": int(pred),
            "label": "fraud" if pred == 1 else "legit",
            "confidence": float(proba[int(pred)]),
            "fraud_probability": float(proba[1]),
        })

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"predictions": results}),
    }
'''
            zf.writestr("lambda_function.py", handler_code)
            zf.writestr("model.pkl", model_bytes)
            zf.writestr("scaler.pkl", scaler_bytes)

        zip_bytes = buf.getvalue()
        model_b64 = ""
        scaler_b64 = ""

    print(f"Lambda zip size: {len(zip_bytes):,} bytes")

    # Check if zip is too large for direct upload (50MB limit)
    if len(zip_bytes) > 50_000_000:
        print("ERROR: Zip too large for Lambda. Use a container image instead.")
        return

    # Lambda needs numpy+sklearn — use a Lambda layer or container
    # For sklearn, we need a Lambda layer. Let's check if we can use
    # the sklearn layer from AWS.
    # Actually, sklearn is NOT available in Lambda by default.
    # We need to use a container image or a layer.
    # Let's use a Docker container image for Lambda instead.
    print("\nNote: sklearn/numpy require a Lambda layer or container image.")
    print("Deploying as a container-based Lambda function...")

    # Create ECR repo
    ecr = session.client("ecr")
    repo_name = "airt-fraud-detection"
    try:
        ecr.create_repository(repositoryName=repo_name)
        print(f"Created ECR repo: {repo_name}")
    except ecr.exceptions.RepositoryAlreadyExistsException:
        print(f"ECR repo exists: {repo_name}")

    repo_uri = f"{account_id}.dkr.ecr.{args.region}.amazonaws.com/{repo_name}"

    # Create Dockerfile and build
    import tempfile
    import subprocess

    with tempfile.TemporaryDirectory() as tmpdir:
        # Dockerfile
        dockerfile = f"""
FROM public.ecr.aws/lambda/python:3.11

COPY model.pkl scaler.pkl ${{LAMBDA_TASK_ROOT}}/
COPY lambda_function.py ${{LAMBDA_TASK_ROOT}}/

RUN pip install "numpy<2" scikit-learn --only-binary :all: --target "${{LAMBDA_TASK_ROOT}}"

CMD ["lambda_function.handler"]
"""
        with open(os.path.join(tmpdir, "Dockerfile"), "w") as f:
            f.write(dockerfile)

        # Copy model files
        import shutil
        shutil.copy(os.path.join(args.model_dir, "model.pkl"), tmpdir)
        shutil.copy(os.path.join(args.model_dir, "scaler.pkl"), tmpdir)

        # Write handler
        handler_code = '''
import json
import os
import pickle

_model = None
_scaler = None


def _load():
    global _model, _scaler
    if _model is None:
        base = os.environ.get("LAMBDA_TASK_ROOT", ".")
        with open(os.path.join(base, "model.pkl"), "rb") as f:
            _model = pickle.load(f)
        with open(os.path.join(base, "scaler.pkl"), "rb") as f:
            _scaler = pickle.load(f)


def handler(event, context):
    """Lambda handler for fraud detection."""
    _load()

    if isinstance(event.get("body"), str):
        body = json.loads(event["body"])
    elif isinstance(event.get("body"), dict):
        body = event["body"]
    else:
        body = event

    if "instances" in body:
        features = [inst["features"] for inst in body["instances"]]
    elif "features" in body:
        features = [body["features"]]
    elif isinstance(body, list):
        features = body
    else:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Unsupported format: {list(body.keys())}"}),
        }

    import numpy as np
    X = np.array(features, dtype=np.float64)
    scaled = _scaler.transform(X)
    predictions = _model.predict(scaled)
    probabilities = _model.predict_proba(scaled)

    results = []
    for pred, proba in zip(predictions, probabilities):
        results.append({
            "class": int(pred),
            "label": "fraud" if pred == 1 else "legit",
            "confidence": float(proba[int(pred)]),
            "fraud_probability": float(proba[1]),
        })

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"predictions": results}),
    }
'''
        with open(os.path.join(tmpdir, "lambda_function.py"), "w") as f:
            f.write(handler_code)

        # Docker login to ECR
        print("Logging into ECR...")
        token = ecr.get_authorization_token()
        auth = token["authorizationData"][0]
        registry = auth["proxyEndpoint"]

        subprocess.run(
            f"aws ecr get-login-password --profile {args.profile} --region {args.region} | "
            f"docker login --username AWS --password-stdin {registry}",
            shell=True, check=True, capture_output=True,
        )

        # Build and push
        tag = f"{repo_uri}:latest"
        print(f"Building Docker image: {tag}")
        subprocess.run(
            ["docker", "build", "--platform", "linux/amd64", "--provenance=false", "-t", tag, tmpdir],
            check=True,
        )
        print("Pushing to ECR...")
        subprocess.run(["docker", "push", tag], check=True)

    # Create/update Lambda function
    lam = session.client("lambda")
    try:
        lam.delete_function(FunctionName=args.function_name)
        print(f"Deleted existing function: {args.function_name}")
        import time
        time.sleep(2)
    except lam.exceptions.ResourceNotFoundException:
        pass

    print(f"Creating Lambda function: {args.function_name}")
    response = lam.create_function(
        FunctionName=args.function_name,
        Role=role_arn,
        Code={"ImageUri": tag},
        PackageType="Image",
        Timeout=30,
        MemorySize=512,
    )
    print(f"Function created: {response['FunctionArn']}")

    # Wait for function to be active
    print("Waiting for function to be active...")
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=args.function_name)

    # Create function URL (public, no auth for testing)
    try:
        url_response = lam.create_function_url_config(
            FunctionName=args.function_name,
            AuthType="NONE",
        )
        function_url = url_response["FunctionUrl"]
    except lam.exceptions.ResourceConflictException:
        url_response = lam.get_function_url_config(FunctionName=args.function_name)
        function_url = url_response["FunctionUrl"]

    # Add permission for public access
    try:
        lam.add_permission(
            FunctionName=args.function_name,
            StatementId="FunctionURLAllowPublicAccess",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
    except lam.exceptions.ResourceConflictException:
        pass

    print(f"\n{'=' * 60}")
    print(f"DEPLOYED SUCCESSFULLY")
    print(f"{'=' * 60}")
    print(f"Function URL: {function_url}")
    print(f"\nTest with curl:")
    print(f'  curl -X POST {function_url} \\')
    print(f'    -H "Content-Type: application/json" \\')
    print(f'    -d \'{{"features": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]}}\'')

    # Save endpoint info
    info = {
        "function_name": args.function_name,
        "function_url": function_url,
        "region": args.region,
        "profile": args.profile,
        "account_id": account_id,
    }
    with open("endpoint_info.json", "w") as f:
        json.dump(info, f, indent=2)
    print(f"\nEndpoint info saved to endpoint_info.json")


if __name__ == "__main__":
    main()
