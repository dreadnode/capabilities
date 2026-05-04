---
name: salesforce-aura-testing
description: Salesforce Aura guest user CRUD enumeration on Experience Cloud communities. Prevents the common miss of testing reads-only when write permissions are independently misconfigured. Use when Salesforce community Aura endpoint responds to unauthenticated requests.
user_invocable: true
---

# Salesforce Aura Guest CRUD Enumeration

When a Salesforce Experience Cloud Aura endpoint responds to guest requests, test **all four CRUD operations independently on every accessible object type**. Read and write permissions are configured separately — testing only reads is the #1 miss on Salesforce targets.

## Usage

```
/salesforce-aura-testing <community-url>
```

## The Rule

When `getConfigData` succeeds unauthenticated, extract the `apiNamesToKeyPrefixes` map. This is your testing roadmap. For every object in the map, test Create, Read, Update, and Delete independently. A 2024 real-world miss: getConfigData returned 200+ object types including Case — read testing returned "inaccessible" so the tester moved on. Another researcher tested `saveRecord` on Case and got guest Create permission. Medium severity finding.

**Read success does NOT imply write failure. Write success does NOT imply read success. Test both.**

## Execution

### Step 1: Confirm guest Aura access

POST to `<community>/s/sfsites/aura` with `getConfigData` descriptor. If `"state":"SUCCESS"`, proceed. Extract `apiNamesToKeyPrefixes` — every key is an object to test.

Note: some orgs reject `aura://` descriptor prefix but accept `serviceComponent://`. Try both.

### Step 2: Prioritize objects

Test these first (highest bounty value):
- **Case** (500) — most commonly misconfigured, guest users legitimately create cases
- **Contact** (003) / **Lead** (00Q) — PII creation
- **EmailMessage** (02s) — email injection
- **ContentDocument** (069) / **Attachment** (00P) — file operations
- **Custom objects** (`*__c`) — weakest access controls
- **User** (005) / **NetworkMember** (0DO) — identity access

### Step 3: Test CRUD per object

For each object, test all four operations via the community Aura endpoint:

**Read** (two controllers):
- `DetailController/ACTION$getRecord` with a record ID (use leaked IDs from VF CSS paths, or guest user's own 005 ID)
- `SelectableListDataProvider/ACTION$getItems` with `entityNameOrId` (returns lists without needing a specific ID)

**Create** (the commonly missed operation):
- `DetailController/ACTION$saveRecord` with `recordInput.apiName` set to the object and minimal required fields
- For Case: `{"apiName":"Case","fields":{"Subject":"test","Description":"authorized security test"}}`

**Update**:
- Same `saveRecord` but include an `Id` field pointing to an existing record

**Delete**:
- `RecordUiController/deleteRecord` with a `recordId`

### Step 4: Interpret responses

| Response | Meaning |
|----------|---------|
| `"state":"SUCCESS"` + record data | Guest has permission — **finding** |
| `"state":"SUCCESS"` + `"inaccessible":true` | Controller accessible, record-level deny — test OTHER records and WRITE ops |
| `"state":"ERROR"` + "no access to Apex class" | Controller exists, profile-restricted — not exploitable from guest |
| Empty actions / warning only | Controller not registered — move to next |
| Internal server error + Error ID | Object exists in org, controller tried but failed — may indicate partial access |

**Critical**: `"inaccessible":true` on a read does NOT mean writes will also fail. The finding that was missed had exactly this pattern — reads returned inaccessible, but creates succeeded.

### Step 5: Test all communities in the same org

Same Salesforce org can host multiple communities at different paths (`/s/`, `/developer/s/`, `/customer/`, `/portal/`). Each community can have a different guest user profile with different object permissions. Test every community independently.

## What NOT to waste time on

- `getConfigData` info disclosure alone is not reportable (standard Salesforce behavior)
- `/services/data/` API version listing is informational
- Org ID / user ID leaks from VF CSS paths — useful as seeds for record ID testing, not findings themselves
- Guest user reading its own User record — default behavior, not a permission escalation
