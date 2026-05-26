---
name: php-filter-chain-oracle
description: Leak file contents via PHP filter chain error-based oracle using memory exhaustion differentials. Use when PHP target has file inclusion or php:// wrapper access, even without direct output.
---

# PHP Filter Chain Oracle

## Pattern
- PHP target with user-controlled path in `include`, `require`, `file_get_contents`, or `readfile`
- `php://filter` wrapper accepted (test: `php://filter/resource=/etc/passwd`)
- No direct file content output (blind LFI scenario)
- Differential error responses observable (500 vs 200, different error messages)

## Workflow

### 1. Confirm php:// wrapper access
```bash
curl -s "https://target.com/endpoint?file=php://filter/resource=/etc/passwd"
# vs
curl -s "https://target.com/endpoint?file=/etc/passwd"
```

**Checkpoint:** If both return identical errors, the wrapper may be blocked. If different responses, the wrapper is processed.

### 2. Exploit iconv filter chains as byte oracle
1. Chain `convert.iconv.UTF8.UCS-4LE` filters to expand data exponentially
2. Use `dechunk` filter as byte oracle — parses hex chars differently than non-hex
3. If target byte is hex `[0-9a-f]`: `dechunk` processes it, chain continues → memory exhaustion → 500
4. If target byte is non-hex: `dechunk` fails early → no exhaustion → 200
5. Use `convert.iconv.UNICODE.CP930` + `string.rot13` to shift non-leading bytes into detectable position

```
php://filter/convert.iconv.UTF8.UCS-4LE|convert.iconv.UTF8.UCS-4LE|...|dechunk/resource=/etc/passwd
```
Automate with: `php_filter_chains_oracle_exploit` (github.com/synacktiv/php_filter_chains_oracle_exploit)

**Checkpoint:** Verify the oracle is consistent by testing the same byte position 3 times. If responses differ across runs, network jitter or caching may interfere.

## Indicators
- Differential response: 500 (memory limit) vs 200 for different filter chains
- Consistent oracle across repeated requests for same byte position
- Byte-by-byte file content reconstructable from error pattern

## Chain With
- ssti-error-based-detection (if PHP template engine found via file read)

## Reference
https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle
