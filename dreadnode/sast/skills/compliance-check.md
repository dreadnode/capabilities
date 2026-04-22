---
name: compliance-check
description: Check code against compliance frameworks including PCI-DSS, SOC2, HIPAA, and GDPR requirements. Use when performing compliance audits, generating compliance reports, mapping controls to code, or validating regulatory requirements.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Compliance Security Checks

## When to Use

Use this skill when:
- Auditing code for compliance requirements
- Generating compliance reports for auditors
- Mapping security controls to code implementation
- Validating PCI-DSS, SOC2, HIPAA, or GDPR compliance
- Preparing for security audits
- Documenting compliance evidence

## When NOT to Use

Do NOT use for:
- General security vulnerability scanning (use semgrep, codeql, sarif-parsing)
- Business logic analysis
- Performance optimization
- Functional testing

## Compliance Frameworks

### PCI-DSS (Payment Card Industry Data Security Standard)

**Applicability:** Systems that store, process, or transmit credit card data

**Key Requirements:**

| Requirement | Description | Code Checks |
|-------------|-------------|-------------|
| **1.2** | Firewall configuration | Network boundary enforcement |
| **2.2** | Secure configurations | No default credentials, hardened configs |
| **3.4** | Encrypt cardholder data | Encryption at rest and in transit |
| **4.1** | Use strong cryptography | TLS 1.2+, strong ciphers |
| **6.2** | Patch vulnerabilities | No known CVEs in dependencies |
| **6.5** | Secure development | Input validation, output encoding |
| **8.2** | Strong authentication | Password complexity, MFA |
| **10.2** | Audit logging | All access to cardholder data logged |

### SOC2 (Service Organization Control 2)

**Applicability:** SaaS and cloud service providers

**Trust Service Criteria:**

| Criteria | Focus | Code Checks |
|----------|-------|-------------|
| **Security** | System protection | Authentication, authorization, encryption |
| **Availability** | System uptime | Error handling, failover, monitoring |
| **Processing Integrity** | Accurate processing | Input validation, transaction logging |
| **Confidentiality** | Data protection | Encryption, access controls |
| **Privacy** | PII handling | Data minimization, consent, retention |

### HIPAA (Health Insurance Portability and Accountability Act)

**Applicability:** Systems handling Protected Health Information (PHI)

**Key Safeguards:**

| Safeguard | Requirement | Code Checks |
|-----------|-------------|-------------|
| **164.308** | Administrative | Access controls, audit logs |
| **164.310** | Physical | Workstation security (limited code relevance) |
| **164.312** | Technical | Encryption, authentication, audit trails |
| **164.316** | Documentation | Policy documentation, risk assessments |

### GDPR (General Data Protection Regulation)

**Applicability:** Systems processing EU residents' personal data

**Key Principles:**

| Principle | Requirement | Code Checks |
|-----------|-------------|-------------|
| **Lawfulness** | Consent management | Consent tracking, withdrawal mechanisms |
| **Purpose Limitation** | Specified purposes only | Data access controls |
| **Data Minimization** | Collect only necessary data | Database schema review |
| **Accuracy** | Keep data accurate | Update mechanisms, validation |
| **Storage Limitation** | Retention policies | Auto-deletion, archival processes |
| **Integrity & Confidentiality** | Security measures | Encryption, access controls |
| **Accountability** | Demonstrate compliance | Audit logs, data processing records |

## PCI-DSS Compliance Checks

### Requirement 3: Protect Stored Cardholder Data

#### Check 1: Credit Card Data Storage

```bash
# Find potential credit card storage
rg -i "credit_card|card_number|cvv|card_verification" . -t py -t js -t sql

# Check for PAN (Primary Account Number) in code
rg "\d{13,19}" . -t py -t js | grep -i "card\|pan\|payment"
```

**Compliant Pattern:**
```python
# NEVER store CVV, only tokenized PAN
import stripe

# Store token, not actual card number
token = stripe.Token.create(card={
    "number": card_number,  # Stripe handles this
    "exp_month": exp_month,
    "exp_year": exp_year,
    "cvc": cvv,
})

# Store only token in database
Payment.objects.create(
    user=user,
    stripe_token=token.id,  # Token, not card number
    amount=amount
)
```

#### Check 2: Encryption at Rest

```bash
# Check for encryption in database models
rg "EncryptedField|encrypt|cipher" . -t py -t js

# Check for TDE (Transparent Data Encryption) in configs
rg "encrypt|tde" . -t sql -t yaml -t conf
```

**Compliant Pattern:**
```python
# Use encrypted fields for sensitive data
from django_cryptography.fields import encrypt

class Payment(models.Model):
    # Encrypted at application level
    cardholder_name = encrypt(models.CharField(max_length=255))
    last_four = models.CharField(max_length=4)  # Only last 4 digits
    # NEVER store full PAN
```

#### Check 3: Encryption in Transit

```bash
# Check for TLS enforcement
rg "ssl|tls|https" . -t py -t js -t conf

# Find insecure HTTP usage
rg "http://.*api|requests\.get\(.*http://" . -t py
```

**Compliant Pattern:**
```python
# Enforce TLS 1.2+
import ssl
import requests

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED

response = requests.get(url, verify=True)  # Verify certificates
```

### Requirement 6: Secure Development

#### Check 4: Input Validation

```bash
# Find input without validation
rg "request\.(args|form|json|query)" . -t py -A 3 | grep -v "validate\|clean\|sanitize"

# Find SQL injection risks
rg "execute\(.*%|execute\(.*\+" . -t py
```

**Compliant Pattern:**
```python
from marshmallow import Schema, fields, validate

class PaymentSchema(Schema):
    amount = fields.Decimal(required=True, validate=validate.Range(min=0.01))
    currency = fields.Str(required=True, validate=validate.OneOf(['USD', 'EUR']))

schema = PaymentSchema()
data = schema.load(request.json)  # Validates input
```

### Requirement 8: Strong Authentication

#### Check 5: Password Requirements

```bash
# Check for password policy enforcement
rg "password.*length|password.*complexity" . -t py -t js

# Check for weak hashing
rg "md5|sha1|hashlib\.md5|hashlib\.sha1" . -t py
```

**Compliant Pattern:**
```python
import re
from passlib.hash import bcrypt

def validate_password(password):
    # PCI-DSS requires: 7+ chars, alpha + numeric
    if len(password) < 7:
        raise ValueError("Password must be at least 7 characters")
    if not re.search(r'[a-zA-Z]', password):
        raise ValueError("Password must contain letters")
    if not re.search(r'\d', password):
        raise ValueError("Password must contain numbers")

def hash_password(password):
    # Use bcrypt with sufficient rounds
    return bcrypt.hash(password, rounds=12)
```

### Requirement 10: Track and Monitor Access

#### Check 6: Audit Logging

```bash
# Find access to cardholder data without logging
rg "card_number|payment_method" . -t py -A 5 | grep -v "log\|audit"

# Check for comprehensive logging
rg "logger\.|log\." . -t py -t js
```

**Compliant Pattern:**
```python
import logging
import structlog

logger = structlog.get_logger()

def access_payment_data(user, payment_id):
    payment = Payment.objects.get(id=payment_id)

    # Log all access to cardholder data
    logger.info(
        "cardholder_data_access",
        user_id=user.id,
        payment_id=payment_id,
        ip_address=request.remote_addr,
        timestamp=datetime.utcnow().isoformat(),
        action="view_payment"
    )

    return payment
```

## SOC2 Compliance Checks

### CC6.1: Logical Access Controls

#### Check 1: Authentication Implementation

```bash
# Check for authentication enforcement
rg "@login_required|@authenticate|require_auth" . -t py -t js

# Find endpoints without authentication
rg "@app\.route|@get|@post" . -t py -B 2 | grep -v "login_required\|auth"
```

**Compliant Pattern:**
```python
from functools import wraps
from flask import session, abort

def require_authentication(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            abort(401)
        return f(*args, **kwargs)
    return decorated

@app.route('/api/sensitive-data')
@require_authentication  # SOC2 control
def get_sensitive_data():
    return jsonify(data)
```

### CC6.6: Encryption

#### Check 2: Data Encryption

```bash
# Check for encryption at rest
rg "encrypt|AES|cipher" . -t py -t js

# Check for encryption in transit
rg "ssl_context|SSLContext|https" . -t py
```

**Compliant Pattern:**
```python
from cryptography.fernet import Fernet

class EncryptedData(models.Model):
    # Encrypt sensitive fields
    encryption_key = models.BinaryField()
    encrypted_value = models.BinaryField()

    def set_value(self, plaintext):
        f = Fernet(self.encryption_key)
        self.encrypted_value = f.encrypt(plaintext.encode())

    def get_value(self):
        f = Fernet(self.encryption_key)
        return f.decrypt(self.encrypted_value).decode()
```

### CC7.2: System Monitoring

#### Check 3: Error Monitoring

```bash
# Check for error tracking
rg "sentry|rollbar|bugsnag|error.*track" . -t py -t js

# Check for logging
rg "logging\.error|console\.error|logger\.error" . -t py -t js
```

**Compliant Pattern:**
```python
import sentry_sdk

sentry_sdk.init(dsn="...", traces_sample_rate=1.0)

@app.errorhandler(Exception)
def handle_exception(e):
    # Log to monitoring service (SOC2 requirement)
    sentry_sdk.capture_exception(e)
    logger.error("Unhandled exception", exc_info=e)
    return "Internal server error", 500
```

## HIPAA Compliance Checks

### 164.312(a)(1): Access Control

#### Check 1: Unique User Identification

```bash
# Check for user identification in logs
rg "log.*user_id|audit.*user|access.*user_id" . -t py -t js
```

**Compliant Pattern:**
```python
def access_phi(user, patient_id):
    # HIPAA: Log all PHI access with user ID
    audit_log.info(
        "phi_access",
        user_id=user.id,
        user_role=user.role,
        patient_id=patient_id,
        action="view_medical_record",
        timestamp=datetime.utcnow(),
        ip_address=request.remote_addr
    )

    return MedicalRecord.objects.get(patient_id=patient_id)
```

### 164.312(a)(2)(iv): Encryption

#### Check 2: PHI Encryption

```bash
# Find PHI storage
rg -i "ssn|social_security|diagnosis|medical_record|health_info" . -t py

# Check for encryption
rg "encrypt|cipher|AES" . -t py -A 3 | grep -B 3 "ssn\|medical\|health"
```

**Compliant Pattern:**
```python
from cryptography.fernet import Fernet

class MedicalRecord(models.Model):
    patient_id = models.IntegerField()
    # PHI must be encrypted (HIPAA 164.312)
    encrypted_diagnosis = models.BinaryField()
    encrypted_ssn = models.BinaryField()
    encryption_key = models.BinaryField()

    def set_diagnosis(self, diagnosis):
        f = Fernet(self.encryption_key)
        self.encrypted_diagnosis = f.encrypt(diagnosis.encode())
```

### 164.312(b): Audit Controls

#### Check 3: Audit Trail

```bash
# Check for comprehensive audit logging
rg "audit|log.*access|activity.*log" . -t py -t js
```

**Compliant Pattern:**
```python
class PHIAuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user_id = models.IntegerField()
    patient_id = models.IntegerField()
    action = models.CharField(max_length=100)  # view, create, update, delete
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()

    # HIPAA: Retain audit logs for 6 years
    class Meta:
        indexes = [
            models.Index(fields=['timestamp', 'patient_id']),
        ]
```

## GDPR Compliance Checks

### Article 17: Right to Erasure

#### Check 1: Data Deletion Implementation

```bash
# Find user deletion logic
rg "delete.*user|remove.*user|erase.*data" . -t py -t js

# Check for cascading deletes
rg "on_delete|CASCADE|SET_NULL" . -t py
```

**Compliant Pattern:**
```python
from django.db import models

class User(models.Model):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    gdpr_deletion_requested = models.BooleanField(default=False)

    def request_deletion(self):
        # GDPR Article 17: Right to erasure
        self.gdpr_deletion_requested = True
        self.save()

        # Delete personal data
        self.email = f"deleted_{self.id}@deleted.com"
        self.name = "[DELETED]"
        self.save()

        # Delete related data
        self.orders.all().delete()
        self.activity_logs.all().delete()
```

### Article 20: Right to Data Portability

#### Check 2: Data Export Functionality

```bash
# Find data export features
rg "export.*data|download.*data|data_export" . -t py -t js
```

**Compliant Pattern:**
```python
import json

def export_user_data(user):
    # GDPR Article 20: Data portability
    data = {
        "personal_info": {
            "email": user.email,
            "name": user.name,
            "created_at": user.created_at.isoformat(),
        },
        "orders": [
            {
                "id": order.id,
                "date": order.created_at.isoformat(),
                "total": str(order.total),
            }
            for order in user.orders.all()
        ],
        "activity_log": [
            {
                "action": log.action,
                "timestamp": log.timestamp.isoformat(),
            }
            for log in user.activity_logs.all()
        ],
    }

    return json.dumps(data, indent=2)
```

### Article 32: Security of Processing

#### Check 3: Pseudonymization

```bash
# Check for pseudonymization techniques
rg "hash.*user_id|anonymize|pseudonym" . -t py -t js
```

**Compliant Pattern:**
```python
import hashlib
import hmac

SECRET_KEY = os.environ['PSEUDONYM_KEY']

def pseudonymize_user_id(user_id):
    # GDPR Article 32: Pseudonymization
    return hmac.new(
        SECRET_KEY.encode(),
        str(user_id).encode(),
        hashlib.sha256
    ).hexdigest()

# Use in analytics without revealing identity
analytics.track(
    user_id=pseudonymize_user_id(user.id),
    event="page_view"
)
```

## Automated Compliance Scanning

```bash
# Generate compliance report
cat > compliance_scan.sh << 'EOF'
#!/bin/bash

echo "=== PCI-DSS Scan ==="
echo "Checking for hardcoded card numbers..."
rg "\d{13,19}" . -t py -t js | grep -i "card\|pan"

echo "Checking for weak crypto..."
rg "md5|sha1|des" . -t py -t js

echo "=== HIPAA Scan ==="
echo "Checking for PHI encryption..."
rg -i "ssn|diagnosis|medical" . -t py | head -20

echo "=== GDPR Scan ==="
echo "Checking for data deletion logic..."
rg "delete.*user|right.*erasure" . -t py

echo "=== SOC2 Scan ==="
echo "Checking for audit logging..."
rg "audit_log|access_log" . -t py
EOF

chmod +x compliance_scan.sh
./compliance_scan.sh
```

## Compliance Report Template

```markdown
# Compliance Audit Report
**Framework:** PCI-DSS 4.0
**Date:** 2026-01-31
**Auditor:** Security Team
**Scope:** Payment processing application

## Executive Summary
- **Compliant Requirements:** 10/12
- **Non-Compliant:** 2 (Req 3.4, Req 10.2)
- **Remediation Required:** Yes

## Requirement Assessment

### ✅ Requirement 3.2: Do not store sensitive authentication data
**Status:** COMPLIANT
**Evidence:**
- Code review shows no CVV/CVV2 storage
- Only tokenized PANs stored via Stripe
- File: `payments/models.py:45-67`

### ❌ Requirement 3.4: Render PAN unreadable
**Status:** NON-COMPLIANT
**Finding:** Cardholder name stored in plaintext
**File:** `payments/models.py:52`
**Remediation:** Encrypt cardholder_name field
**Priority:** HIGH

### ✅ Requirement 8.2: Strong authentication
**Status:** COMPLIANT
**Evidence:**
- Password complexity enforced
- MFA available for all users
- File: `auth/validators.py:12-28`

### ❌ Requirement 10.2: Audit trail
**Status:** NON-COMPLIANT
**Finding:** Payment access not logged
**File:** `payments/views.py:89`
**Remediation:** Add audit logging for all cardholder data access
**Priority:** CRITICAL

## Remediation Plan
1. **Critical:** Implement audit logging (2 days)
2. **High:** Encrypt cardholder name (1 day)
3. **Medium:** Review exception handling (3 days)
```

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "We'll become compliant before the audit" | Compliance is ongoing, not a one-time event |
| "That's a minor requirement" | All requirements are mandatory for certification |
| "We're too small to need compliance" | Legal obligations apply regardless of company size |
| "Auditors won't check code" | Modern audits include code review and penetration testing |
| "Compliance slows us down" | Non-compliance results in fines, breaches, and loss of business |

## Resources

- PCI-DSS 4.0: https://www.pcisecuritystandards.org/
- SOC2 Framework: https://www.aicpa.org/soc4so
- HIPAA Security Rule: https://www.hhs.gov/hipaa/for-professionals/security/
- GDPR: https://gdpr-info.eu/
- Related Skills: triage-priority, secure-code-patterns
