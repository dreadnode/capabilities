---
name: secure-code-patterns
description: Language-specific secure coding patterns and anti-patterns for input validation, output encoding, authentication, cryptography, and error handling. Use when reviewing code for security best practices or educating developers on secure coding.
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Secure Code Patterns

## When to Use

Use this skill when:
- Reviewing code for security best practices
- Providing secure coding guidance to developers
- Identifying common vulnerability patterns
- Refactoring insecure code to secure patterns
- Creating coding standards and guidelines
- Training developers on secure coding

## When NOT to Use

Do NOT use for:
- Automated vulnerability scanning (use semgrep, codeql)
- Finding specific CVEs in dependencies (use supply-chain-security)
- Threat modeling or architecture review (use threat-modeling)
- Compliance checking (use compliance-check)

## Input Validation

### Pattern: Allowlist Validation

**Insecure:**
```python
# Blocklist - incomplete, easily bypassed
username = request.form['username']
if 'script' in username or 'drop' in username:
    return "Invalid"
# Bypass: <SCRIPT>, DROP, ScRiPt
```

**Secure:**
```python
# Allowlist - explicit allowed characters
import re
username = request.form['username']
if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
    return "Username must be 3-20 alphanumeric characters", 400
```

### Pattern: Type Validation

**Insecure:**
```javascript
// No validation - type coercion vulnerabilities
const age = req.body.age;
if (age > 18) {
    grantAccess();  // Bypass: age = "100" (string)
}
```

**Secure:**
```javascript
// Strong type validation
const age = parseInt(req.body.age, 10);
if (isNaN(age) || age < 0 || age > 120) {
    return res.status(400).json({ error: "Invalid age" });
}
if (age >= 18) {
    grantAccess();
}
```

### Pattern: Length Limits

**Insecure:**
```python
# No length limit - DoS via large input
data = request.get_json()
process(data['message'])  # 100GB string crashes server
```

**Secure:**
```python
# Enforce length limits
MAX_MESSAGE_LENGTH = 10000
data = request.get_json()
message = data.get('message', '')

if len(message) > MAX_MESSAGE_LENGTH:
    return "Message too long", 400

process(message)
```

## Output Encoding

### Pattern: Context-Aware Encoding

**Insecure:**
```javascript
// No encoding - XSS
const name = req.query.name;
res.send(`<h1>Hello ${name}</h1>`);  // XSS: ?name=<script>alert(1)</script>
```

**Secure:**
```javascript
// HTML context encoding
const escapeHtml = (str) =>
    str.replace(/[&<>"']/g, (m) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;',
        '"': '&quot;', "'": '&#39;'
    })[m]);

const name = req.query.name;
res.send(`<h1>Hello ${escapeHtml(name)}</h1>`);
```

**Context-specific encoding:**

```javascript
// HTML context
const html = `<div>${escapeHtml(userInput)}</div>`;

// JavaScript context
const js = `<script>var name = "${escapeJs(userInput)}";</script>`;

// URL context
const url = `/search?q=${encodeURIComponent(userInput)}`;

// CSS context (avoid user input in CSS if possible)
const css = `<div style="color: ${escapeCss(userInput)}"></div>`;
```

### Pattern: Safe Template Rendering

**Insecure:**
```python
# String concatenation - XSS
html = f"<div>{user_input}</div>"
```

**Secure:**
```python
# Use template engine with auto-escaping
from jinja2 import Template
template = Template("<div>{{ user_input }}</div>")
html = template.render(user_input=user_input)  # Auto-escaped
```

## Authentication & Sessions

### Pattern: Secure Password Storage

**Insecure:**
```python
# Plain text or weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # BROKEN
```

**Secure:**
```python
# Use bcrypt or Argon2
import bcrypt

# Hashing
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# Verification
if bcrypt.checkpw(password.encode(), stored_hash):
    login_success()
```

### Pattern: Secure Session Management

**Insecure:**
```javascript
// Predictable session IDs
const sessionId = `${userId}_${Date.now()}`;  // Predictable
res.cookie('session', sessionId);  // Missing security flags
```

**Secure:**
```javascript
// Cryptographically random session ID
const crypto = require('crypto');
const sessionId = crypto.randomBytes(32).toString('hex');

res.cookie('session', sessionId, {
    httpOnly: true,    // Prevents XSS access
    secure: true,      // HTTPS only
    sameSite: 'strict', // CSRF protection
    maxAge: 3600000    // 1 hour expiration
});
```

### Pattern: Multi-Factor Authentication

**Insecure:**
```python
# Only password authentication
if check_password(username, password):
    login_user(username)
```

**Secure:**
```python
# TOTP-based MFA
import pyotp

def login(username, password, totp_code):
    if not check_password(username, password):
        return False

    user = get_user(username)
    totp = pyotp.TOTP(user.mfa_secret)

    if not totp.verify(totp_code, valid_window=1):
        return False

    create_session(username)
    return True
```

## SQL Injection Prevention

### Pattern: Parameterized Queries

**Insecure:**
```python
# String concatenation - SQL injection
user_id = request.args.get('id')
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# SQLi: ?id=1 OR 1=1
```

**Secure:**
```python
# Parameterized query
user_id = request.args.get('id')
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

**Framework-specific:**

```python
# Django ORM (safe)
User.objects.filter(id=user_id)

# SQLAlchemy (safe)
session.query(User).filter(User.id == user_id).first()

# Raw SQL with params (safe)
session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
```

### Pattern: Avoid Dynamic Table/Column Names

**Insecure:**
```python
# User controls table name - SQL injection
table = request.args.get('table')
cursor.execute(f"SELECT * FROM {table}")  # SQLi: ?table=users; DROP TABLE users--
```

**Secure:**
```python
# Allowlist approach
ALLOWED_TABLES = {'users', 'orders', 'products'}
table = request.args.get('table')

if table not in ALLOWED_TABLES:
    return "Invalid table", 400

# Use query builder or careful escaping
cursor.execute(f"SELECT * FROM {table}")  # Safe after validation
```

## Command Injection Prevention

### Pattern: Avoid Shell Execution

**Insecure:**
```python
# User input to shell - command injection
filename = request.args.get('file')
os.system(f"cat {filename}")  # Injection: ?file=file.txt; rm -rf /
```

**Secure:**
```python
# Use subprocess with list (no shell)
import subprocess
filename = request.args.get('file')

# Validate filename
if not re.match(r'^[a-zA-Z0-9_.-]+$', filename):
    return "Invalid filename", 400

# No shell=True - safe
result = subprocess.run(['cat', filename], capture_output=True, text=True)
```

### Pattern: Never Use shell=True with User Input

**Insecure:**
```python
subprocess.run(f"grep {pattern} file.txt", shell=True)  # DANGEROUS
```

**Secure:**
```python
# Option 1: Use list without shell
subprocess.run(['grep', pattern, 'file.txt'])

# Option 2: Use shlex.quote() if shell required
import shlex
subprocess.run(f"grep {shlex.quote(pattern)} file.txt", shell=True)
```

## Path Traversal Prevention

### Pattern: Validate and Normalize Paths

**Insecure:**
```python
# No validation - path traversal
filename = request.args.get('file')
with open(f"/var/www/uploads/{filename}") as f:
    return f.read()
# Attack: ?file=../../../etc/passwd
```

**Secure:**
```python
import os
from pathlib import Path

BASE_DIR = Path("/var/www/uploads")
filename = request.args.get('file')

# Resolve to absolute path
file_path = (BASE_DIR / filename).resolve()

# Ensure it's still within BASE_DIR
if not file_path.is_relative_to(BASE_DIR):
    return "Access denied", 403

with open(file_path) as f:
    return f.read()
```

## Cryptography

### Pattern: Use Strong Ciphers

**Insecure:**
```python
# Weak encryption
from Crypto.Cipher import DES  # BROKEN
cipher = DES.new(key, DES.MODE_ECB)  # BROKEN MODE
```

**Secure:**
```python
# AES-GCM (authenticated encryption)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
aesgcm = AESGCM(key)

# Encrypt
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

# Decrypt
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
```

### Pattern: Secure Random Generation

**Insecure:**
```python
# Predictable randomness
import random
token = ''.join(random.choices('0123456789', k=6))  # PREDICTABLE
```

**Secure:**
```python
# Cryptographically secure random
import secrets
token = secrets.token_urlsafe(32)  # 256 bits of randomness
```

### Pattern: Key Derivation

**Insecure:**
```python
# Direct password use as key
key = password.encode()  # WRONG
```

**Secure:**
```python
# PBKDF2 key derivation
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=480000,  # OWASP recommendation
)
key = kdf.derive(password.encode())
```

## Error Handling

### Pattern: Generic Error Messages

**Insecure:**
```python
# Verbose errors reveal system info
try:
    user = User.objects.get(username=username)
except User.DoesNotExist:
    return "User 'admin' does not exist", 404  # Leaks username existence
```

**Secure:**
```python
# Generic error message
try:
    user = User.objects.get(username=username)
    if not check_password(password, user.password_hash):
        raise AuthError()
except (User.DoesNotExist, AuthError):
    return "Invalid username or password", 401  # Generic message
```

### Pattern: Log Errors, Don't Display Them

**Insecure:**
```javascript
app.get('/api/data', async (req, res) => {
    try {
        const data = await database.query('...');
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.stack });  // Leaks stack trace
    }
});
```

**Secure:**
```javascript
app.get('/api/data', async (req, res) => {
    try {
        const data = await database.query('...');
        res.json(data);
    } catch (err) {
        console.error('Database error:', err);  // Log internally
        res.status(500).json({ error: "Internal server error" });  // Generic message
    }
});
```

## Authorization

### Pattern: Check Authorization on Every Request

**Insecure:**
```python
# Check once, assume it persists
if not is_admin(user):
    return "Access denied", 403

# Later in code (different function)
delete_user(target_user_id)  # No re-check!
```

**Secure:**
```python
# Decorator enforces authorization
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin(current_user):
            return "Access denied", 403
        return f(*args, **kwargs)
    return decorated_function

@require_admin
def delete_user(user_id):
    User.objects.filter(id=user_id).delete()
```

### Pattern: Prevent IDOR

**Insecure:**
```python
# No ownership check - IDOR
@app.route('/api/orders/<order_id>')
def get_order(order_id):
    order = Order.objects.get(id=order_id)  # Any user can access any order
    return jsonify(order)
```

**Secure:**
```python
# Verify ownership
@app.route('/api/orders/<order_id>')
@login_required
def get_order(order_id):
    order = Order.objects.get(id=order_id)

    if order.user_id != current_user.id:
        return "Access denied", 403

    return jsonify(order)
```

## Language-Specific Patterns

### Python

```python
# Use secrets module for tokens
import secrets
token = secrets.token_urlsafe(32)

# Use parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Use subprocess safely
subprocess.run(['command', arg1, arg2])  # No shell=True

# Validate file paths
file_path = (BASE_DIR / filename).resolve()
if not file_path.is_relative_to(BASE_DIR):
    raise SecurityError()
```

### JavaScript/Node.js

```javascript
// Use crypto for randomness
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');

// Parameterized queries (using pg)
client.query('SELECT * FROM users WHERE id = $1', [userId]);

// Content Security Policy
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
    }
}));

// CSRF protection
const csrf = require('csurf');
app.use(csrf({ cookie: true }));
```

### Go

```go
// Parameterized queries
db.Query("SELECT * FROM users WHERE id = $1", userID)

// Command execution without shell
cmd := exec.Command("command", arg1, arg2)
output, err := cmd.Output()

// Secure random
token := make([]byte, 32)
_, err := rand.Read(token)
tokenStr := base64.URLEncoding.EncodeToString(token)

// Path validation
filepath.Clean(path)
if !strings.HasPrefix(filepath.Clean(path), baseDir) {
    return errors.New("access denied")
}
```

### Java

```java
// Parameterized queries
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

// Secure random
SecureRandom random = new SecureRandom();
byte[] token = new byte[32];
random.nextBytes(token);

// Password hashing (Spring Security)
PasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);

// Path validation
Path normalizedPath = Paths.get(basePath, userInput).normalize();
if (!normalizedPath.startsWith(basePath)) {
    throw new SecurityException("Access denied");
}
```

## Detection Patterns

```bash
# Find potential SQL injection
rg "execute\(.*%|execute\(.*\+|execute\(.*format" . -t py -t js

# Find command injection
rg "system\(|exec\(|shell=True|eval\(" . -t py -t js

# Find hardcoded secrets
rg -i "password\s*=\s*['\"]|api_key\s*=\s*['\"]" . -t py -t js

# Find path traversal
rg "open\(.*request\.|readFile\(.*req\." . -t py -t js

# Find XSS vulnerabilities
rg "innerHTML|document.write|eval\(" . -t js
```

## Rationalizations to Reject

| Shortcut | Why It's Wrong |
|----------|----------------|
| "Input validation is the frontend's job" | Never trust client-side validation; always validate server-side |
| "We're behind a firewall, internal traffic is safe" | Insider threats and lateral movement after initial compromise |
| "Escaping once is enough" | Context matters; HTML escaping doesn't prevent SQL injection |
| "Framework handles security automatically" | Frameworks provide tools, but developers must use them correctly |
| "It's just test code" | Test code often runs in production, or gets copied to production code |

## Resources

- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- CWE Top 25: https://cwe.mitre.org/top25/
- NIST Secure Coding: https://www.nist.gov/itl/ssd/software-quality-group/secure-coding
- SEI CERT Coding Standards: https://wiki.sei.cmu.edu/confluence/display/seccode
- Related Skills: semgrep, codeql, semgrep-rule-creator, sharp-edges
