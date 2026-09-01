---
name: TSP-policy-skill
description: Design, implement, and configure Salesforce Transaction Security Policies (TSPs) — Apex EventCondition classes, Condition Builder policies, and Flow-based follow-up actions (Slack alert, notify manager, create case) — based on Salesforce's "Essential Transaction Security Policies" implementation guide. Use when the user wants to detect/block sensitive report exports, list view or API access to classified fields, geo/impossible-travel logins, weak TLS ciphers, SSO bypass, large data exports by profile, guest user abuse, privilege escalation, unapproved API clients, cumulative mass access (DLP), or threat detection alerts in Salesforce.
---

# Transaction Security Policy (TSP) Skill

Reference for building Salesforce Transaction Security Policies (Event Monitoring → Transaction Security Policy) across 6 security lenses.

Sources:
- **Canonical catalog** (authoritative for editions, licensing, policy list/descriptions): Salesforce Help — "Essential Transaction Security Policies to Enhance Your Security Posture", `https://help.salesforce.com/s/articleView?id=xcloud.top_transaction_security_policies.htm&type=5`. This page is a high-level table only — it has no Apex or step-by-step.
- **Implementation detail** (Apex classes, Condition Builder steps, Flow follow-ups): the "Essential Transaction Security Policies" Implementation Guide (Summer '25) PDF at `claude-testing/artifacts/Top TSPs Implementation Guide.pdf`. Its code samples contain bugs — see "Known bugs in the source samples".
- **Preferred deployment path** (packaged templates): the **Transaction Security Policy Accelerator** — see next section.

## Transaction Security Policy Accelerator (prefer this over hand-authoring)

The **TSP Accelerator** is a Salesforce Shield Lightning app tab (alongside Shield Home, Data Detect, Field Audit Trail, Event Monitoring, Platform Encryption) that ships a library of **prebuilt, deploy-ready policy templates** — the same policies documented below, already defined so you skip the Apex/Condition Builder authoring and the source-sample bugs entirely. **When the org has the Accelerator, use it first**; fall back to manual authoring (rest of this skill) only for orgs without it or for custom policies not in the catalog.

- **Layout**: policies are grouped as cards under the same 6 security-use-case lenses used below. Each card shows a **status badge**: `Not Deployed`, `Deployed / Not Enabled` (orange), or `Deployed / Enabled` (green), plus a `Deploy` button and, once deployed, a `View in Setup` link and an `Enable` button.
- **Deploy → Enable is a deliberate two-step, safe-by-default flow**:
  1. Click **Deploy** on a card → **Step 1: Policy Details** (description + triggering event).
  2. **Step 2: Configure & Deploy** — set the notification recipient(s). A warning states the **policy deploys as *Disabled***.
  3. Success toast confirms deployment; badge → `Deployed / Not Enabled`.
  4. Click **Enable** (or activate via **Setup → Transaction Security Policies**) → badge → `Deployed / Enabled`.
  This mirrors the manual best practice ("start Alert-Only / not-live, validate, then enable") — do not skip straight to enabling in production.
- **Accelerator naming ≠ PDF naming** (map when the user references either):
  - Data Protection: **Detect High Risk Data in API Queries / List View / Report Export** ("high-risk sensitivity level" terminology) ↔ the classified-data (Confidential) policies below.
  - Access Control: **Detect Impossible Travel Scenarios**, **Detect Logins Based on TLS Cipher Suite**, **Detect Logins from Non Approved Countries**, **Monitor Internal Logins that Bypass SSO**.
  - Security Model: **Detect Large API Queries by a Guest User**, **Detect Privilege Escalation**, **Detect Report Exports by Unapproved Profiles**.
  - Integration: **Detect API Access from Unapproved Third Party Apps**.
  - DLP: **Total Access and Export Detection for List Views**, **Total Access and Export Detection for Report Exports** (the cumulative/mass-access pattern, split by event type).
  - Monitoring: seven threat/anomaly templates — **Detect API Anomaly**, **Detect Credential Stuffing**, **Detect Dormant User**, **Detect Guest User Anomaly**, **Detect Login Anomaly**, **Detect Report Anomaly**, **Detect Session Hijacking** (Threat Detection Events). Note the Accelerator enumerates the *specific* threat-detection event types — use these real names over the PDF's generic "Login Anomaly Event".

## Real-time events vs. EventLogFile (know which side you're on)

Event Monitoring has **two delivery paths**, and TSPs live on only one of them. Do not confuse them.

- **Real-time streaming events** (`*EventStream` platform events, e.g. `ReportEventStream`, `ApiEventStream`, `LoginEventStream`) — fire synchronously as the action happens. **This is the only path TSPs use**: a policy's `evaluate()`/Condition Builder runs against the live event and can **`Block`** the action. Follow-up Flows subscribe to these streams.
- **EventLogFile (ELF)** — a **retrospective, batch** CSV log of the same event types, exposed via the `EventLogFile` sObject over REST/SOAP. **It cannot block anything** and is **not** what a TSP evaluates. Use it for forensics, tuning, and after-the-fact detection.

**How the two work together (the useful part):** ELF is the best tool to **validate and tune a TSP before you set it to `Block`**. Deploy the policy as Alert-Only / `None`, let events accumulate, then query ELF for the corresponding `EventType` (e.g. `ReportExport`, `API`, `Login`, `URI`, `RestApi`, `BulkApi`) to measure real hit rates and false positives on production traffic — then graduate to `Block` with confidence. ELF also covers events with **no** real-time equivalent, so it fills detection gaps the streaming policies can't.

### EventLogFile essentials (from the REST API doc)

- **Query** (REST): `GET /services/data/v{version}/query/?q=SELECT+Id,EventType,LogDate,LogFileLength,Interval,Sequence,LogFileContentType+FROM+EventLogFile+WHERE+EventType='ReportExport'+AND+LogDate=Yesterday`
- **Download the log blob**: append `/LogFile` to the record URI → `GET /services/data/v{version}/sobjects/EventLogFile/{Id}/LogFile` (returns CSV; `LogFileContentType` = `text/csv`). Via CLI: `sf data query` for the metadata, then a REST GET (or `sf api request rest`) for the blob.
- **Key fields**: `EventType`, `LogDate`, `LogFile` (blob), `LogFileContentType`, `LogFileLength`, `Interval` (`Hourly` or `Daily`), `Sequence` (ordinal within an hour/day), `CreatedDate` (use this to find *newly generated* files — including latent ones).
- **Latency** (this is why ELF ≠ real-time): **Daily** files generate during off-peak hours the **day after** the event (≥1 day lag). **Hourly** files typically land **3–6 hours** after the event, sometimes longer. Files exist only for event types that actually occurred that hour/day. **Always re-query for new/latent files** rather than assuming a fixed schedule.
- **Interval note**: Hourly logs can be incomplete during site switches/instance refreshes/outages — for a **complete** record use the **Daily** files. Log data is read-only (you can delete a whole file, not individual rows), and is a source of truth but **not durable** (loss possible during outages).
- **Retention**: Shield / Event Monitoring add-on → **1 year** (then auto-deleted). Developer Edition / Trial → **1 day**.
- **Permissions**: `View Event Log Files` **and** `API Enabled` (or `View All Data`). Same Shield/Event Monitoring add-on licensing as the rest of this skill.
- **Hourly Event Log Files** must be enabled in Setup (real-time high-volume feature) if you need sub-daily latency; otherwise only Daily files are produced.

## Prerequisites (check these FIRST)

- **Editions**: available in **Enterprise, Unlimited, and Developer** Editions (Lightning Experience, and Salesforce Classic where present).
- **License**: Transaction Security + real-time events require **Salesforce Shield or the Salesforce Event Monitoring add-on**. Without it the events below do not stream and no policy can be created. Confirm the org has it before promising any of this. (Developer Edition includes it for testing.)
- **Apex test coverage**: any `TxnSecurity.EventCondition` class must have a deployable test class (75% coverage) to reach production.
- **Verify API names against the target org**: event names, fields, and Custom Metadata Type/field API names in the source guide are examples and in several cases inconsistent (see "Known bugs in the source samples"). Validate with `sf sobject describe` or the LSP before deploying.
- **Enablement order**: enable event streaming/storage in Event Manager *before* creating the policy, or the event won't appear in the picklist.

## General Workflow (applies to every TSP)

> **Verified against a live org (Developer Edition, API 67.0)** — see "Org-verified facts" at the bottom for the exact `TransactionSecurityPolicy` field values and `EventName` picklist. Use those API names, not the guide's prose labels.

1. **Enable event streaming**: Setup → Event Manager → enable streaming (and storage where relevant) for the required event type. The policy's **`EventName`** must be one of the org's supported values (verified list): `ReportEvent`, `ApiEvent`, `ListViewEvent`, `LoginEvent`, `LoginAsEvent`, `AdminSetupEvent`, and the async **`…EventStore`** events — `PermissionSetEventStore`, `BulkApiResultEventStore`, `FileEventStore`, `CredentialStuffingEventStore`, `SessionHijackingEventStore`, `ReportAnomalyEventStore`, `ApiAnomalyEventStore`, `GuestUserAnomalyEventStore`, `LoginAnomalyEventStore`, `UniversalAnomalyEventStore`.
2. **Author logic**:
   - Simple field comparisons → Setup → Security → Event Monitoring → Transaction Security Policy → **New → Condition Builder**.
   - Complex/cross-object logic → Setup → Apex Classes → new class implementing `TxnSecurity.EventCondition` with `public Boolean evaluate(SObject event)` → then create the policy with **New → Apex** and select that class. `evaluate` returns `true` when the condition is met (the configured actions then fire). **Use `TxnSecurity.EventCondition`, not the deprecated `TxnSecurity.PolicyCondition`** — old blog/StackExchange samples often show the legacy interface (`evaluate(TxnSecurity.Event e)`), which no longer maps to real-time events.
3. **Create the policy**: choose the Event, select condition/Apex class, then set the **Actions** and (optionally) a custom notification message, Description, and Status = `Enabled`.
   - **Actions are not just `Block`.** Depending on the event, a policy can: send **Notifications** (email + in-app, to selected recipients), **Block** the operation, **End Session**, **Freeze** the user, and — for **Login** events — **Require higher-assurance / Multi-Factor** (step-up auth). For Login risk, an MFA step-up is often better UX than a hard `Block`.
   - **Not every event can Block.** Synchronous events (Report, List View, API, Login, etc.) support Block/enforce actions. **Asynchronous events — the Threat Detection / anomaly events (`*AnomalyEvent`, `SessionHijackingEvent`, `CredentialStuffingEvent`) — are informational and can only Notify**, never Block. Design those policies as alert-only.
4. **Always start with notify-only (no enforce action)** in production; add `Block`/`End Session`/MFA only after validating no false positives (Salesforce's stated best practice). Use ELF (above) to measure hit rate during this pilot phase.
5. **Layer follow-up automation via Flow** (Platform Event–Triggered Flow on the relevant `*EventStream`) for anything beyond the default notification:
   - Decision element gate: `Transaction Security Policy ID` **Is Set** = True. **Then branch on `PolicyOutcome`** — its value reflects the action actually taken (e.g. `Block`, `NoAction`). ⚠️ During an alert-only pilot the outcome is **not** `Block`, so gating on `PolicyOutcome Equals Block` will silently never fire; gate on `Policy ID Is Set` alone (or the outcome your policy really emits) until you turn on enforcement.
   - Common follow-up branches: Slack message (Action → Slack → Send Slack Message, set Slack App/Workspace/Conversation ID), Notify Manager (Get Records on User for ManagerId → Get Records for manager Email → Send Email), Create Case (Case Actions → New Case).

## Policy Catalog by Security Lens

### Data Protection & Classification
- **Detect Report Exports Containing Classified (PII) Data** — Report Event; Apex checks `ReportEvent.Operation == 'ReportExported'` and cross-references `FieldDefinition.SecurityClassification = 'Confidential'` for the queried entity (e.g., Contact). Action: Block + email + Slack + case.
- **Prevent List View Access to Classified Fields** — List View Event; Apex checks `ListViewEvent.QueriedEntities` + `ColumnHeaders` against confidential `FieldDefinition`s. Action: Block.
- **Detect Large-Volume API Queries with Classified Fields** — API Event; Apex checks `ApiEvent.QueriedEntities`/`Query` against confidential fields. Action: Block.

### Access Control (Authentication)
- **Login from Outside Approved Geo Region** — Login Event; Condition Builder: `Country` **does not equal** `US, CA` (adjust list). Note: weak signal alone — pair with MFA/IP restrictions/SSO. Action: Block.
- **Impossible Travel Detection** — Login Event; requires custom object `LoginLocation__c` (User__c, LoginTime__c, Country__c, City__c, IPAddress__c) populated via an Apex invocable (`StoreLoginLocation`) called from a Platform Event–Triggered Flow on Login Event; TSP Apex class (`DetectImpossibleTravel`) compares current login to last stored login and flags if City/Country changed within 30 minutes. Action: None (alert-only) + email/Slack/manager/case.
- **Block Logins Based on TLS Cipher Suite** — Login Event; Custom Metadata Type `Allowed_Cipher_Suite__mdt` (field `Cipher_Suite__c`) stores approved ciphers; Apex class checks negotiated cipher against the allowlist. Action: Block.
- **Monitor Internal Logins that Bypass SSO** — Login Event; Condition Builder: `LoginType` **Equals** `Application` AND `UserType` **Equals** `Standard`. Action: Block (or None to just alert) + Slack/email/manager/case.

### Security Model (Authorization)
- **Restrict Large Data Exports to Specific User Profiles** — Report Event; Custom Metadata Type `Approved_Profile__mdt` (field `Profile_Name__c`) stores allowlisted profiles (e.g., "Marketing User"); Apex blocks export if exporting user's `Profile.Name` not in the allowlist.
- **Restrict High Volume API Queries by Guest User** — API Event; Apex checks user's ProfileId against known Guest Profile Id(s) and `rowsProcessed` against a threshold (e.g., 1000). Action: Block.
- **Privilege Escalation Alert** — policy `EventName` = `PermissionSetEventStore` (the "Permission Set Event"; note the standalone `PermissionSetEvent` object is not directly queryable in-org — bind the policy to the `…EventStore` name); detect users granted elevated privileges **outside a controlled change process** — either assignment of the **Admin profile** or a **Permission Set containing "Modify All Data"**. Condition Builder covers the permission-set case: `Permission List` **Contains** `ModifyAllData`; cover the Admin-profile-assignment case separately (Apex or an added condition). Action: Block + Slack/email/case.

### Integration
- **Block API Access from Specific Third-Party Applications** — API Event; Condition Builder: `Client` **equals** e.g. `PostmanRuntime`. Action: Block.
- **Block API Access from Unapproved Third-Party Applications** — API Event; Custom Metadata Type `ApprovedApiClient__mdt` (field `ClientName__c`) stores an allowlist (e.g., MuleSoft, Salesforce CLI); Apex blocks any `ApiEvent.Client` not in the allowlist. Preferred over the single-app version — deny-by-default.

### Data Loss Prevention (DLP)
- **Cumulative Mass Access/Export Behavior Detection** — detects slow-drip exfiltration across sessions. Requires: custom object `RecordAccessLog__c` (User__c, RecordId__c, AccessTime__c); Apex invocable (`LogMultipleRecordAccess`) parses `ListViewEvent.Records` JSON and logs each accessed record ID, wired via a Platform Event–Triggered Flow; TSP Apex class (`DetectHighVolumeAccessTSP`) sums unique `RecordId__c` per user in a trailing 24h window and flags if over threshold (e.g., 10,000). Action: None (alert-only) — pattern is extensible to ReportEvent/ApiEvent by duplicating Flow+Apex. Note: consider a scheduled Apex cleanup job for log object growth.

### Monitoring
- **Get Alerted on Threat Detection Events** — Login Anomaly Event; Condition Builder: `Score` **Greater than or equal to** `0.5`. Action: None + email/Slack/case. Leverages Salesforce's built-in ML-based anomaly scoring.

## Follow-Up Action Recipes (Flow patterns)

All triggered off a Platform Event–Triggered Flow on the relevant `*EventStream`, gated by a Decision checking `Transaction Security Policy ID Is Set = True`. Only add an `AND PolicyOutcome Equals Block` clause if the policy is actually enforcing `Block` — for alert-only/pilot policies (and for async anomaly events, which never Block) that clause makes the Flow never fire, so gate on `Policy ID Is Set` alone.

1. **Slack Notification**: Action → Slack → Send Slack Message; set Slack App, Workspace, Execute Action As = `Slack App`, Slack Conversation ID = channel (e.g. `#security-alerts`), message body with user/timestamp context.
2. **Notify User's Manager**: Get Records (User, filter User ID = triggering event's User ID) → store `ManagerId` in a variable → Get Records (User, filter User ID = that ManagerId variable) → store `Email` in a variable → Send Email action to that address, Sender Type = `DefaultWorkflowUser`.
3. **Create a Case for Investigation**: Case Actions → New Case; set Status = New, Subject/Description with context (user ID, IP, timestamp).

## Known bugs in the source samples (fix before deploying)

The guide's Apex/config samples are illustrative and several do **not** compile or behave as described. When implementing, correct these:

- **TLS Cipher Suite policy**: the guide's Apex is a mislabeled copy of the profile-export class — it casts to `ReportEvent` and checks `Approved_Profile__mdt`, and never inspects a cipher suite. You must write real logic against the Login Event's TLS/cipher fields (verify the field name in-org) and query the `Allowed_Cipher_Suite__mdt` allowlist.
- **Impossible Travel**: `StoreLoginLocation` writes `LoginTime__c` but `DetectImpossibleTravel` queries `EventDate__c` on `LoginLocation__c`. Pick one field name and use it in both places.
- **DLP mass access**: object is `RecordAccessLog__c` but the sample Apex references `RecordAccessLog_c__c` (stray `_c`). Fix the object API name throughout.
- **Guest high-volume API**: `RECORD_COUNT_THRESHOLD` is commented out yet referenced (won't compile) — uncomment it. Setup text says "Permission Set Event" but the code casts to `ApiEvent` — use API Event. Hardcoded Guest Profile Id must be replaced with the org's real value.
- **Unapproved API clients**: CMDT setup creates `ApprovedApiClient` (singular) but the Apex queries `ApprovedApiClients__mdt` (plural) with field `ClientName__c` — make the object/field API names match. Setup also says enable "Report Events"; it should be **API Events**.
- **Classification scope**: the classified-data policies filter only `SecurityClassification = 'Confidential'`, but the use-cases describe "Sensitive" data. Salesforce supports multiple levels (Public / Internal / Confidential / Restricted / MissionCritical). Widen the filter to the levels your org actually uses.
- **"Login Anomaly Event"**: the guide's prose label is not the policy API name. As a **policy `EventName`** the value is `LoginAnomalyEventStore` (there is also `UniversalAnomalyEventStore`); the underlying queryable event objects are `SessionHijackingEvent`, `CredentialStuffingEvent`, `ReportAnomalyEvent`, `ApiAnomalyEvent`, `GuestUserAnomalyEvent` (all confirmed to exist in-org). Bind the policy to the `…EventStore` name and confirm the score field in the target org.

## Key Cautions (carry these into any implementation)
- Apex/Flow samples in the guide are **illustrative only**, not officially supported — test in sandbox before production.
- Always pilot new policies with Action = `None`/Alert-Only before moving to `Block`.
- Geo/IP-based detections are weak standalone signals (VPN/proxy spoofing) — pair with MFA, IP restrictions, SSO conditional access.
- Impossible-travel and mass-access detections can false-positive on legitimate third-party/API integrations acting on a user's behalf.
- Prefer Custom Metadata Types over hardcoded lists/IDs for allowlists (profiles, cipher suites, API clients) — no redeploy needed, environment-safe across sandbox/production.
- High-volume custom logging objects (`RecordAccessLog__c`, `LoginLocation__c`) need a retention/cleanup strategy (e.g., scheduled Apex purge).

## Org-verified facts (Developer Edition, API 67.0 — 2026)

Confirmed by describing objects and querying the live org:

- **`TransactionSecurityPolicy` fields** (use these exact API names when creating policies via Metadata/Tooling API):
  - `Type` picklist = `CustomApexPolicy` | `CustomConditionBuilderPolicy` (these are the two authoring paths).
  - `State` picklist = `Enabled` | `Disabled` (this is the "Enabled/Not Enabled" the Accelerator badges reflect — not "Active").
  - `EventName` picklist = the verified list in General Workflow step 1.
  - Actions are **not** a simple field: they live in **`ActionConfig`** (a JSON textarea) plus **`BlockMessage`** (the block text) — consistent with the multi-action model (Notify/Block/EndSession/Freeze/MFA), not a lone None/Block toggle.
  - Category field `EventType` = `AuditTrail | Login | Entity | DataExport | AccessResource`.
- **A default policy already ships**: `sfdc_default_ReportExport_Protection` — `EventName=ReportEvent`, `Type=CustomConditionBuilderPolicy`, `State=Enabled`. Inspect it as a working Condition Builder reference before hand-building the report-export policy.
- **Objects present & queryable**: `EventLogFile`, `ReportEvent`, `ApiEvent`, `LoginEvent`, `ListViewEvent`, and all anomaly events. `PermissionSetEvent` is **not** directly queryable (bind policies to `PermissionSetEventStore`).
- **Where stored real-time events actually live (verified by running two report exports):**
  - For **base events** (`ReportEvent`, `ApiEvent`, `LoginEvent`, `ListViewEvent`) there is **no `…EventStore` big object** — a `ReportEventStore` does not exist. Once storage is enabled in Event Manager, the **stored, queryable object is the event name itself** (`SELECT … FROM ReportEvent`), with `…EventStream` as the streaming twin (`ReportEventStream`).
  - Only the **anomaly/threat family** uses a separate stored big object: `ReportAnomalyEventStore`, `ApiAnomalyEventStore`, `SessionHijackingEventStore`, `CredentialStuffingEventStore`, `GuestUserAnomalyEventStore`, `LoginAnomalyEventStore`, `UniversalAnomalyEventStore`, plus `PermissionSetEventStore`, `BulkApiResultEventStore`, `FileEventStore`. (Bind policies to these `…EventStore` names; query them for stored history.)
  - **`ReportEvent` verified fields**: `EventIdentifier`, `EventDate`, `Operation`, `Username`, `RowsProcessed`, `QueriedEntities`. **There is no `ReportName` field** — report identity comes via `QueriedEntities` (the report's primary entity, e.g. `Opportunity`) and the report Id, not a name. Report-export detection keys off **`Operation = 'ReportExported'`** (the run event is `Operation = 'ReportRunFromLightning'`) — both confirmed captured in real time, within seconds of the action.
- **Enablement is Setup-UI + permissions, not CLI**: "Generate event log files" / hourly ELF / per-event Storage+Streaming toggles live in Setup → Event Monitoring Settings and Event Manager; no `sf` metadata/CLI switch flips them. Real-time **Storage** populates the queryable event object within seconds; **ELF** CSV files lag ≥1 day (daily) or 3–6h (hourly).
- **`EventLogFile.EventType`** has ~79 values; verified security-relevant ones include `ReportExport`, `Report`, `MultiBlockReport`, `AsyncReportRun`, `API`, `RestApi`, `ApexRestApi`, `BulkApi`, `BulkApi2`, `Login`, `LoginAs`, `URI`. `Interval` = `Hourly` | `Daily`.
- **⚠️ No ELF data in this org**: `SELECT EventType, COUNT(Id) FROM EventLogFile GROUP BY EventType` returned **0 rows** — event log files aren't being generated here (this Developer org isn't streaming ELF, or nothing has been processed). The ELF-based tuning workflow can be *described* but **could not be exercised** on the test org as-is; verify ELF generation is enabled before relying on it.
- **⚠️ Creating/editing a TSP requires the "Modify Transaction Security Policies" permission — the real cause of `INSUFFICIENT_ACCESS`**: deploying a hand-authored `CustomApexPolicy` on `ReportEvent` (with its `TxnSecurity.EventCondition` Apex class already present in the org) fails with **`You don't have sufficient access to perform this action.`** on the `TransactionSecurityPolicy` component **when the running user lacks the "Modify Transaction Security Policies" system permission.** This was reproduced identically on both an unlicensed org and a Shield-licensed org, so it is **NOT** a Shield/Event Monitoring license gate, **NOT** feature provisioning (the seeded `sfdc_default_ReportExport_Protection` policy is present and Enabled), and **NOT** covered by the usual admin perms (`AuthorApex`, `CustomizeApplication`, `ModifyAllData`, `ViewEventLogFiles` all `true` still failed). The `TransactionSecurityPolicy` Tooling object is a metadata-container type (only `Metadata`/`FullName` are createable), so a Tooling create is just another metadata deploy and is gated the same way.

  **Fix — grant "Modify Transaction Security Policies" (a full System Administrator does NOT have it by default):**
  1. It is a **system permission that cannot be assigned directly** — it must be enabled **inside a Permission Set or Profile**. Create/edit a Permission Set, check **System Permissions → Modify Transaction Security Policies**, and save.
  2. **Assign** that Permission Set to the running/deploy user via **Permission Set Assignments**.
  3. Manage policies in **Setup → Quick Find → Transaction Security Policies** (Condition Builder or Apex), or now deploy them via Metadata API.

  **✅ Empirically verified**: after granting this permission (via a dedicated permission set), the exact same `CustomApexPolicy` on `ReportEvent` that previously failed deployed cleanly — **3/3 components (2 Apex classes + policy) in one deploy**, landing as `State=Enabled`, `ActionConfig` all-false (alert-only, non-disruptive). The permission was the sole missing piece.

  API name of the permission (verified via `PermissionSet` describe): **`PermissionsModifyTransactionSecurityPolicies`** — the field on the `PermissionSet`/`Profile` SObject, and the `<userPermissions><name>ModifyTransactionSecurityPolicies</name>` entry in Permission Set metadata. To check whether a user already has it: `SELECT Id FROM PermissionSetAssignment WHERE AssigneeId = '<userId>' AND PermissionSet.PermissionsModifyTransactionSecurityPolicies = true`. Regardless of path, deploy/keep the Apex condition class **before** the policy references it — a policy deployed alone yields `In field: apexClass - no ApexClass named <X> found`.
