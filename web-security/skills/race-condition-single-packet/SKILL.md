---
name: race-condition-single-packet
description: Single-packet race conditions for exploiting multi-step flows via precise HTTP/2 request synchronization. Use when target has state-changing operations with limit checks, balance validation, or multi-step logic.
---

# Race Condition (Single-Packet Attack)

## Pattern
- Coupon/discount/promo code application (use-once logic)
- Money transfers or balance deductions (insufficient funds check)
- Vote/like/rating limits (count-based restrictions)
- 2FA or email verification token validation
- Inventory/stock checks during purchase
- Rate limit bypass on authentication endpoints

## Probe
**HTTP/2 single-packet technique:**
1. Open one H2 connection to target
2. Prepare N requests (e.g. 20x "apply coupon") but withhold final DATA frames
3. Pause ~100ms to trigger Nagle's algorithm batching
4. Send all END_STREAM frames simultaneously in one TCP packet
5. All N requests arrive within ~1ms, defeating server-side locks

**HTTP/1.1 last-byte sync:**
1. Send N requests on N connections, withholding final byte of each
2. Send all final bytes simultaneously
3. Less precise (~4ms spread) but works without H2

Tools: Turbo Intruder (single-packet attack mode), `curl --parallel` with H2.

## Indicators
- Resource consumed N times from N parallel requests (coupon applied twice)
- Balance decremented below zero or multiple times in one operation
- Limit bypassed (N+1 votes, multiple password attempts)

## Chain With
- orm-filter-data-leak (race-accelerated boolean oracle extraction)

## Reference
https://portswigger.net/research/smashing-the-state-machine
