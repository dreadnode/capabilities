# Feature flag and experiment mining

Feature flags are target generators. They expose backend workflows before they are visible in the UI, explain dormant routes, and identify rollout states where authorization assumptions are changing.

## Look for

- LaunchDarkly: `LDClient`, `variation`, `allFlags`, `ld_key`
- Firebase Remote Config: `FirebaseRemoteConfig`, `getBoolean`, `getString`, `fetchAndActivate`
- Split.io: `SplitClient`, `getTreatment`
- Optimizely: `Optimizely`, `isFeatureEnabled`
- Statsig: `Statsig`, `checkGate`, `getExperiment`
- Unleash: `Unleash`, `isEnabled`
- custom config endpoints: `/features`, `/experiments`, `/config`, `/remote-config`, `/bootstrap`, `/flags`
- local flag stores: SharedPreferences / DataStore / Room tables named flags, experiments, config, treatments

## Grep

```bash
rg -n \
  -e 'LaunchDarkly|LDClient|FirebaseRemoteConfig|RemoteConfig|SplitClient|Optimizely|Statsig|Unleash' \
  -e 'featureFlag|feature_flag|experiment|variant|treatment|isEnabled|getBoolean|getString|variation|checkGate' \
  -e 'enable_|disable_|rollout|gate|killSwitch|remote_config|fetchAndActivate|allFlags' \
  -e '/features|/experiments|/config|/remote-config|/bootstrap|/flags' \
  "$SRC" > findings/<pkg>/rg-feature-flags.txt
```

## Prioritize flags with security meaning

High signal substrings:

- `recovery`, `reset`, `migrate`, `transfer`, `pair`, `trusted_device`, `device_verification`
- `kyc`, `identity`, `document`, `verification`, `risk`, `fraud`
- `payment`, `checkout`, `refund`, `coupon`, `promo`, `gift`, `wallet`, `limit`
- `family`, `child`, `guardian`, `team`, `org`, `tenant`, `admin`, `role`
- `webview`, `bridge`, `native_bridge`, `external_url`, `deeplink`, `dynamic_link`
- `graphql`, `grpc`, `api_v2`, `new_backend`, `gateway`, `mobile_api`
- `bypass`, `skip`, `fallback`, `debug`, `staging`, `internal`, `dogfood`, `beta`

## How to turn flags into hypotheses

1. Find flag definition and default.
2. Find every call site.
3. Read the enabled and disabled branch.
4. Identify newly exposed endpoint families or workflow verbs.
5. Check whether the flag only hides UI or also changes backend authorization.
6. Record whether remote config can be influenced by account/tenant/device cohort.

Hypothesis examples:

- `enable_device_recovery_v2` gates a new `/recovery/complete` endpoint whose DTO accepts `deviceId` and `trustedDevice`.
- `skip_kyc_for_low_value_transfer` gates a client-only transfer threshold check; backend validation is unknown.
- `new_graphql_checkout` adds persisted mutation hashes for checkout and coupon redemption not present in web UI.

## Validation boundary

Feature flags rarely prove a vulnerability by themselves. They are routing evidence. Most findings remain `needs_backend_validation` until tested under authorized account/tenant conditions.
