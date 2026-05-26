---
name: phone-verification
description: Retrieve SMS verification codes from public or private phone number services. Use when signup, login, recovery, or MFA testing requires SMS verification during authorized web security testing.
---

# Phone Verification

## Workflow

### 1. Try free public numbers first
```
numbers = list_free_phone_numbers(country="all")
```
Use a relevant country filter when the target requires it (e.g., `country="US"`).

### 2. Submit number in target flow
Enter the selected number in the target's SMS verification field.

### 3. Read the inbox
```
messages = read_phone_inbox(phone_number="+1234567890")
```
Use `sender_filter` when the inbox is noisy (e.g., `sender_filter="TargetApp"`).

**Checkpoint:** If no SMS arrives after 30 seconds, retry `read_phone_inbox` up to 3 times with 10s intervals. If still empty, the public number may be blocked -- proceed to step 4.

### 4. Escalate to private number if blocked
```
key = get_credential("sms_provider_api_key")
number = request_private_number(provider="twilio", country="US", api_key=key)
code = poll_private_number(number=number, timeout=60)
```

**Checkpoint:** After extracting the code, verify it is a valid format (typically 4-8 digits) before submitting to the target.

## Rules

- Use only for authorized testing
- Public inboxes are shared -- do not use for sensitive real accounts
- Do not use paid private numbers unless public numbers are rejected or rate-limited
- Store provider API keys with `store_credential` -- never place secrets in prompts or reports
