---
name: race-condition-single-packet
description: Single-packet race conditions for exploiting multi-step flows via precise HTTP/2 request synchronization. Use when target has state-changing operations with limit checks, balance validation, or multi-step logic that may be vulnerable to concurrent execution.
---

# Race Condition (Single-Packet Attack)

## Pattern
- Coupon/discount/promo code application (use-once logic)
- Money transfers or balance deductions (insufficient funds check)
- Vote/like/rating limits (count-based restrictions)
- 2FA or email verification token validation
- Inventory/stock checks during purchase
- Rate limit bypass on authentication endpoints

## Technique

**HTTP/2 single-packet:**
1. Open one H2 connection to target
2. Prepare N requests (e.g. 20x "apply coupon") but withhold final DATA frames
3. Pause ~100ms to trigger Nagle's algorithm batching
4. Send all END_STREAM frames simultaneously in one TCP packet
5. All N requests arrive within ~1ms, defeating server-side locks

```bash
# Using Turbo Intruder (Burp extension) - single-packet mode:
# In Turbo Intruder, select "race/single-packet-attack.py" template
# Set request count to 20, configure the target request, and fire

# Using curl for quick H2 multiplexing test:
seq 1 20 | xargs -P 20 -I{} curl --http2 -s -o /dev/null -w "req={} status=%{http_code}\n" \
  -X POST "https://target.com/api/apply-coupon" \
  -H "Cookie: session=TOKEN" \
  -d "code=PROMO123"
```

**HTTP/1.1 last-byte sync** (when H2 not available):
1. Send N requests on N connections, withholding final byte of each
2. Send all final bytes simultaneously
3. Less precise (~4ms spread) but works without H2

**Checkpoint:** After sending parallel requests, check the resource state (balance, coupon count, vote tally). If the operation applied N times instead of once, the race condition is confirmed.

## Indicators
- Resource consumed N times from N parallel requests (coupon applied twice)
- Balance decremented below zero or multiple times in one operation
- Limit bypassed (N+1 votes, multiple password attempts)

## Chain With
- orm-filter-data-leak (race-accelerated boolean oracle extraction)

## Reference
https://portswigger.net/research/smashing-the-state-machine
