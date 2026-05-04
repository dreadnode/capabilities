---
name: config-and-persistence-review
description: Review iOS configuration surfaces that enable persistence or surveillance — configuration profiles, MDM, TCC grants, provisioning profiles, VPN, root CAs, WebClips, jailbreak indicators, and sideloaded enterprise apps.
---

# Configuration & Persistence Review

## When to Use
- Triage flagged a profile, unusual TCC grant, or sideloaded app
- Incident scoping: what durable footholds exist on this device
- Pre-travel / post-travel posture review for high-risk users
- Device handover / handback audit

## Surface Area (ranked by real-world prevalence)

1. **Configuration profiles** — MDM, supervision, root CAs, VPN, Wi-Fi — the #1 iOS persistence vector
2. **TCC grants** — retained sensitive permissions (camera / mic / location / contacts / photos)
3. **Provisioning profiles** — developer / enterprise signatures enabling sideloaded apps
4. **Sideloaded / enterprise apps** — apps outside the App Store (AltStore, TrollStore, enterprise certs)
5. **Root CAs** — trusted certs enable TLS MitM
6. **VPN / proxy configuration** — traffic diversion, DNS rewriting
7. **WebClips** — home-screen "apps" that are really URL launchers (lookalike / phish)
8. **Accessibility grants** — Switch Control, AssistiveTouch — classic stalkerware footprint
9. **Jailbreak / tweak indicators** — `/etc/apt`, Sileo, Cydia, Dopamine, palera1n artifacts
10. **Apple ID / iCloud state** — Find My, iCloud Backup, account sharing — post-compromise exfil vectors

## Procedure

### 1. Configuration profiles (every single one)
```
mvt_configuration_profiles(source, iocs=<optional>)
```
For each profile, record:
- Display name, identifier, UUID
- Issuer / signer (unsigned profiles are trivially fabricated)
- Installation date
- Payloads (MDM, Wi-Fi, VPN, Certificates, Restrictions, Web Content Filter, DNS)
- Removal policy (`PayloadRemovalDisallowed` = stickier persistence)

Score each profile:
- Known enterprise MDM (Jamf, Intune, Workspace ONE, Kandji, JumpCloud) with matching corp ownership → benign, verify signer
- Apple Beta Software Program / carrier profile → benign
- Self-signed, recent install, MDM payload, remote commands allowed → high priority
- Any profile installing a root CA → high priority (TLS MitM)
- `PayloadRemovalDisallowed=true` on a profile the user can't explain → high priority
- Web Content Filter forcing traffic through a proxy → high priority

### 2. Root CAs + trust store
```
mvt_run_module(source, module="id_status_cache")   # iMessage id_status_cache (ID / cert linkage)
ios_backup_list(backup_dir, path_substring="TrustStore")
```
Extract `TrustStore.sqlite3` if present and enumerate trusted roots. Any non-Apple, non-public-CA root with an enterprise-looking subject → investigate.

### 3. TCC grants (retention audit)
```
mvt_tcc(source)
```
- Apps with Microphone, Camera, or Screen Recording grants that haven't been used in 30+ days → candidate for revocation
- Accessibility grants (AX, Switch Control, AssistiveTouch) to anything non-Apple → high priority; AX grants let an app read any on-screen content
- Location "Always" to apps that don't need background location → at minimum a hygiene issue, sometimes a stalkerware signal

### 4. Provisioning profiles & sideloaded apps
```
mvt_installed_apps(source)
ios_backup_list(backup_dir, path_substring="embedded.mobileprovision")
```
Extract each `embedded.mobileprovision` — it's a CMS-signed plist — via `ios_backup_extract` then `ios_read_plist` after stripping the CMS envelope (or use `security cms -D` offline). For each:
- `AppIDName`, `TeamName`, `TeamIdentifier`
- `ProvisionedDevices` — if your target's UDID is present on an unfamiliar team, someone enrolled them
- `Entitlements` — elevated entitlements (`com.apple.developer.kernel.*`, `com.apple.security.*`) on a random app are a big deal

App categories to flag:
- Enterprise-signed apps whose team doesn't match the organization
- Sideloaded via AltStore / TrollStore / SideStore / Sideloadly
- Apps that don't appear in any App Store (`iTunesMetadata.plist` missing / non-App-Store source)

### 5. VPN / proxy / DNS
Configuration profile payloads already surface VPN + proxy. Additionally:
```
ios_backup_list(backup_dir, path_substring="com.apple.networkextension")
ios_backup_list(backup_dir, path_substring="preferences.plist")
```
Extract relevant plists. Look for:
- PerAppVPN / AlwaysOnVPN configurations
- DNS-over-HTTPS / DoT configurations pointed at unexpected endpoints
- Proxy auto-configs (PAC URLs) served from unknown origins

### 6. WebClips
```
ios_backup_list(backup_dir, path_substring="WebClips")
```
Each WebClip is a plist (`Info.plist`) with `URL`, `Title`, optional `FullScreen`. Attackers seed home-screen WebClips that look like bank / login apps.

### 7. Jailbreak / tweak indicators
Backups don't capture `/Applications` system directories, but some artifacts leak:
- Installed apps named `Sileo`, `Cydia`, `Zebra`, `Installer`, `Dopamine`, `palera1n`
- Bundle IDs with `org.coolstar.`, `com.saurik.`, `xyz.willy.`, `com.opa334.`
- On FFS: `/etc/apt`, `/var/jb`, `/bin/bash`, `/usr/libexec/cydia` presence

Not every jailbreak is malicious, but it materially changes the threat model — note it and adjust downstream findings accordingly.

### 8. iCloud / Apple ID posture
Extract `com.apple.accountsd/Library/Accounts/Accounts4.sqlite` (path varies) and the `com.apple.imservice.ids.FaceTime` / `ids-pair-device-long-term-public-key` keychain items.
- Multiple Apple IDs enrolled → investigate
- Family Sharing / account-sharing configurations unexpectedly present → investigate
- Find My / Stolen Device Protection disabled → hygiene / persistence concern

## Reporting
Group findings by surface (profiles, TCC, sideloaded apps, root CAs, etc.). For each entry state: install date, issuer, removal policy, risk verdict, recommended action (remove profile / revoke TCC / uninstall app / rotate Apple ID / factory reset).

Finish with a survivability table:

| Cleanup action | What it removes |
|---|---|
| Remove profile | That profile only |
| Settings → General → Reset → Reset All Settings | Most profiles, Wi-Fi, VPN |
| Erase All Content and Settings | Profiles, apps, TCC, keychain, Apple-ID-tied data stays in iCloud |
| Device replacement + new Apple ID | Only guarantee against determined supply-chain / iCloud-resident implants |

## Common Pitfalls
- Treating a signed profile as legitimate — signatures only prove "someone with a certificate" installed it
- Missing sticky profiles (`PayloadRemovalDisallowed`) that survive user-initiated settings resets
- Flagging corporate MDM as malicious without checking the issuer against the organization's directory
- Assuming "no jailbreak detected" = device is pristine — Rootless / userland-only tweaks leave far fewer artifacts
- Forgetting iCloud — a fully erased local device can still be repopulated with surveillance from iCloud Backup if iCloud credentials are compromised
