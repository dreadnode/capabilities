# Insecure Defaults: Examples and Counter-Examples

## Fallback Secrets

### VULNERABLE - Report These

```python
# src/auth/jwt.py
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-123')
# App runs with known secret if SECRET_KEY is missing. Attacker forges tokens.
```

```javascript
// config/database.js
const DB_PASSWORD = process.env.DB_PASSWORD || 'admin123';
// Database accepts hardcoded password in production if env var missing.
```

```ruby
# config/secrets.rb
Rails.application.credentials.secret_key_base =
  ENV.fetch('SECRET_KEY_BASE', 'fallback-secret-base')
# Rails session encryption uses weak known key as fallback.
```

### SECURE - Skip These

```python
SECRET_KEY = os.environ['SECRET_KEY']  # Raises KeyError if missing - fail-secure
```

```javascript
if (!process.env.DB_PASSWORD) {
  throw new Error('DB_PASSWORD environment variable required');
}
```

## Default Credentials

### VULNERABLE

```python
def bootstrap_admin():
    if not User.query.filter_by(role='admin').first():
        admin = User(username='admin', password=hash_password('admin123'), role='admin')
        db.session.add(admin)
# Default admin account created on first run with known credentials.
```

### SECURE

```python
def bootstrap_admin():
    username = os.environ['ADMIN_USERNAME']  # Crashes if not configured
    password = os.environ['ADMIN_PASSWORD']
```

## Fail-Open Security

### VULNERABLE

```python
# Default is no authentication
REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'false').lower() == 'true'
```

```javascript
// Default allows requests from any origin
const allowedOrigins = process.env.ALLOWED_ORIGINS || '*';
app.use(cors({ origin: allowedOrigins }));
```

```python
# Debug mode default - stack traces leak info in production
DEBUG = os.getenv('DEBUG', 'true').lower() != 'false'
```

### SECURE

```python
REQUIRE_AUTH = os.getenv('REQUIRE_AUTH', 'true').lower() == 'true'  # Default: true
```

## Weak Crypto

### VULNERABLE

```python
# MD5 for password hashing
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
```

```java
// DES with ECB mode
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
```

### SECURE - Skip

```python
# MD5 for non-security cache key
def cache_key(data):
    return hashlib.md5(data.encode()).hexdigest()  # OK - just cache lookup
```

## Permissive Access

### VULNERABLE

```python
fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o666)  # World-writable
```

```python
response.headers['Access-Control-Allow-Origin'] = '*'
response.headers['Access-Control-Allow-Credentials'] = 'true'
# CORS misconfiguration - allows credential theft from any site
```

## Debug Features

### VULNERABLE

```python
@app.errorhandler(Exception)
def handle_error(error):
    return jsonify({
        'error': str(error),
        'traceback': traceback.format_exc()  # Leaks internal paths
    }), 500
```

```javascript
const server = new ApolloServer({
  introspection: true,   // Schema discovery in production
  playground: true
});
```

### SECURE

```python
@app.errorhandler(Exception)
def handle_error(error):
    logger.exception('Request failed', exc_info=error)  # Logs full trace
    return jsonify({'error': 'Internal server error'}), 500  # Generic to user
```
