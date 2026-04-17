---
name: phone-verification
description: Use when signup, login, recovery, or MFA testing requires SMS verification during authorized web security testing. Prefer free public inboxes first, then paid private numbers only when public numbers are blocked.
---

# Phone Verification

Use the phone verification tools only when a target flow requires an SMS code.

## Workflow

1. Start with free public numbers:
   - `list_free_phone_numbers(country="all")`
   - Use a relevant country filter when the target requires it.
2. Submit the selected number in the target flow.
3. Read the inbox:
   - `read_phone_inbox(phone_number="...")`
   - Use `sender_filter` when the inbox is noisy.
4. If the target blocks public numbers, use a private-number provider:
   - Retrieve the provider API key with `get_credential`.
   - `request_private_number(...)`
   - `poll_private_number(...)`

## Rules

- Use only for authorized testing.
- Public inboxes are shared. Do not use them for sensitive real accounts.
- Do not use paid private numbers unless public numbers are rejected or rate-limited.
- Store provider API keys with `store_credential`; do not place secrets in prompts or reports.
