# Ordering Bugs: Validate-Then-Transform

## Sanitize-Then-Decode (Most Common)

```php
// VULNERABLE: sanitize runs on encoded input, decode undoes it
$input = strip_tags($user_input);      // strips <script>
$input = urldecode($input);            // %3Cscript%3E becomes <script>
echo $input;                           // XSS

// SECURE: decode first, then sanitize
$input = urldecode($user_input);
$input = strip_tags($input);
```

```python
# VULNERABLE: validate then normalize
if not re.search(r'[<>]', user_input):  # clean
    output = html.unescape(user_input)   # &lt;script&gt; → <script>

# SECURE: normalize then validate
normalized = html.unescape(user_input)
if not re.search(r'[<>]', normalized):
    output = normalized
```

## Sanitize-Then-Concatenate

```java
// VULNERABLE: sanitize individual parts, concatenate creates injection
String table = sanitize(request.getParameter("table"));  // "users"
String col = sanitize(request.getParameter("col"));      // "name"
String query = "SELECT " + col + " FROM " + table;
// col = "name FROM users; DROP TABLE users; --" after concatenation

// SECURE: parameterized queries, never concatenate
```

## Sanitize-Then-Template

```javascript
// VULNERABLE: sanitize input, but template engine re-interprets
let safe = escapeHtml(userInput);       // escapes < > & " '
let html = template.render({data: safe}); // template uses {{{data}}} (raw)
// Triple-mustache in Handlebars bypasses escaping

// Also watch for:
// - Jinja2 |safe filter after escaping
// - EJS <%- %> (unescaped) vs <%= %> (escaped)
// - Thymeleaf th:utext (unescaped) vs th:text (escaped)
```

## Sanitize-Then-Normalize (Unicode)

```python
# VULNERABLE: filter then normalize
if '<' not in user_input and '>' not in user_input:
    normalized = unicodedata.normalize('NFKC', user_input)
    # U+FF1C (fullwidth <) normalizes to < after the check passed

# SECURE: normalize first
normalized = unicodedata.normalize('NFKC', user_input)
if '<' not in normalized and '>' not in normalized:
    output = normalized
```

## Second-Order Bypass

```python
# VULNERABLE: sanitize on input, store, retrieve unsanitized later
def submit_comment(request):
    comment = sanitize_xss(request.POST['comment'])
    db.save(comment)  # stored clean

def admin_view(request):
    comments = db.get_all_comments()
    for c in comments:
        send_email(subject="New comment", body=c.text)  # HTML email, no escaping
```

The sanitizer runs at input time, but the stored value is consumed by a different code path that doesn't sanitize. Check: is the sanitized value used in ALL consumers, or only the one the developer was thinking about?
