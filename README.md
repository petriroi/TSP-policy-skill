# TSP-policy-skill

A [Claude Code](https://claude.com/claude-code) skill for designing, implementing, and
configuring **Salesforce Transaction Security Policies (TSPs)** — Apex `EventCondition`
classes, Condition Builder policies, and Flow-based follow-up actions (Slack alert, notify
manager, create case) — based on Salesforce's "Essential Transaction Security Policies"
implementation guide.

## What it covers

- Detecting/blocking sensitive **report exports**, list-view/API access to classified
  fields, geo / impossible-travel logins, weak TLS ciphers, SSO bypass, large data exports
  by profile, guest-user abuse, privilege escalation, unapproved API clients, cumulative
  mass access (DLP), and threat-detection alerts.
- The **Transaction Security Policy Accelerator** (Shield app, prebuilt templates,
  Deploy → Enable flow).
- **Real-time events vs. `EventLogFile`** — which path can block, and how to tune a policy
  with retrospective ELF data before enabling Block.
- **Org-verified facts** — field API names, the `EventName` picklist, the action model, and
  where stored events actually live, all confirmed against a live org.

## Install

Clone into your Claude Code skills directory:

```bash
git clone https://github.com/petriroi/TSP-policy-skill.git ~/.claude/skills/TSP-policy-skill
```

The skill activates automatically when a task matches its description, or invoke it
explicitly with `/TSP-policy-skill`.

## Repository layout

| Path | Contents |
|------|----------|
| `SKILL.md` | The skill itself (instructions Claude loads). |
| `examples/classes/` | Sample `TxnSecurity.EventCondition` Apex class + test for an alert-only report-export policy. |
| `examples/transactionSecurityPolicies/` | The alert-only `CustomApexPolicy` metadata, plus the org's seeded `sfdc_default_ReportExport_Protection` (a `CustomConditionBuilderPolicy`) as a working reference. |
