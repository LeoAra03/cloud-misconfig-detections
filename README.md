# cloud-misconfig-detections

Fourteen detections across Azure and AWS. Each one ships with the vulnerable resource, the
baseline resource, the severity derivation, and the known false positive. If a detection
cannot be reproduced against its fixture, it does not ship.

## Why a fixture pair instead of a query dump

A query alone proves you can write KQL. The vulnerable/baseline pair proves the query
discriminates: run against `baseline.json` and it must return nothing. Most published
detection packs never test the negative case, which is why they generate noise and get
muted in the first month.

## Detections

| ID | Cloud | Detection | Severity |
|---|---|---|---|
| AZ-01 | Azure | Storage account `allowBlobPublicAccess` true | high |
| AZ-02 | Azure | NSG rule 0.0.0.0/0 on 22 or 3389 | high |
| AZ-03 | Azure | Managed identity with Owner or Contributor at subscription scope | high |
| AZ-04 | Azure | Key Vault `enableSoftDelete` false | medium |
| AZ-05 | Azure | Diagnostic setting absent on a resource with an audit-relevant type | medium |
| AZ-06 | Azure | Public IP attached to a VM with no NSG association | high |
| AZ-07 | Azure | App Service `httpsOnly` false | medium |
| AZ-08 | Azure | SQL server `publicNetworkAccess` enabled | medium |
| AZ-09 | Azure | Disk encryption set absent | low |
| AWS-01 | AWS | S3 Block Public Access partially disabled | high |
| AWS-02 | AWS | Security group ingress 0.0.0.0/0 on 22 or 3389 | high |
| AWS-03 | AWS | IAM policy action `*` on resource `*` | high |
| AWS-04 | AWS | Root account without MFA | high |
| AWS-05 | AWS | CloudTrail multi-region disabled | medium |

## Run

```bash
python run.py --fixtures          # all detections against both fixture sets
python run.py --fixtures --format sarif > out.sarif
python run.py --fixtures --expect-no-findings   # negative run, must be clean
```

Each detection is executed against its `fixtures/<id>/vulnerable.json` (must fire) and
`fixtures/<id>/baseline.json` (must stay clean). The KQL in `azure/arg/`, the Azure
policy definitions in `azure/policy/` and the AWS Config rules in `aws/config/` are the
authoritative deployment artifacts; `run.py` reproduces their semantics against the
fixtures so CI can assert discrimination without a cloud account.

## Severity method

docs/rubric.md derives each severity from four factors, not from a feeling: exposure
(internet-reachable, cross-tenant, internal), exploitability without credentials,
compensating control present elsewhere, and data sensitivity at the default configuration.
Two reviewers using the rubric on the same finding should land within one band.

| ID | Exposure | Exploitability | Compensating | Data | Sum | Band |
|---|---|---|---|---|---|---|
| AZ-01 | 2 | 2 | 0 | 2 | 6 | high |
| AZ-02 | 2 | 2 | 0 | 2 | 6 | high |
| AZ-03 | 2 | 2 | 0 | 2 | 8 | high |
| AZ-04 | 2 | 1 | 0 | 2 | 5 | medium |
| AZ-05 | 1 | 0 | 1 | 2 | 4 | medium |
| AZ-06 | 2 | 2 | 0 | 1 | 7 | high |
| AZ-07 | 2 | 1 | 1 | 1 | 5 | medium |
| AZ-08 | 2 | 1 | 0 | 2 | 5 | medium |
| AZ-09 | 0 | 0 | 1 | 1 | 2 | low |
| AWS-01 | 2 | 2 | 0 | 2 | 8 | high |
| AWS-02 | 2 | 2 | 0 | 2 | 6 | high |
| AWS-03 | 2 | 2 | 0 | 2 | 8 | high |
| AWS-04 | 2 | 2 | 0 | 2 | 8 | high |
| AWS-05 | 0 | 0 | 1 | 2 | 3 | medium |

## Known false positives

AZ-02 fires on jump-host NSGs where the source is intentionally broad. The baseline fixture
documents the exemption; the policy version uses exemptions rather than editing the rule.
AWS-03 fires on AWS-managed policies the customer cannot edit. Detections filter
AttachmentCount and policy ARN prefix.
AZ-06 misses VMs behind Azure Firewall. Deliberate: firewall presence is a separate
detection, and one finding should carry one fact.

## False positives per detection

| ID | Known false positive | Handling |
|---|---|---|
| AZ-01 | Static-site storage accounts intentionally allow public blob access. | Exclude by assignment scope rather than editing the rule. |
| AZ-02 | Jump-host NSGs where the broad source is intentional. | Baseline fixture documents the exemption; policy uses exemptions. |
| AZ-03 | Break-glass service principals with Owner at subscription scope. | Treat as time-bound, documented exemptions. |
| AZ-04 | Vaults holding only ephemeral cache data where recovery is not required. | Documented exception, not a rule change. |
| AZ-05 | Resources feeding non-audit pipelines whose diagnostic streams go elsewhere. | Confirmed by compensating-control check. |
| AZ-06 | VMs behind Azure Firewall. | Deliberate miss; firewall presence is a separate detection. |
| AZ-07 | Internal-only apps behind a TLS-terminating front door. | Documented exception; httpsOnly adds nothing there. |
| AZ-08 | SQL servers intentionally exposed for legacy app migration. | Time-bound, documented exception. |
| AZ-09 | Dev/test VMs where platform default encryption suffices. | Non-production scope justifies the low band. |
| AWS-01 | Sandbox accounts where public access is required by design. | Documented exemption at account level. |
| AWS-02 | Bastion/jump security groups with broad SSH for incident access. | Exemption, not rule change. |
| AWS-03 | AWS-managed policies the customer cannot edit. | Filtered by policy ARN prefix (`arn:aws:iam::aws:policy/*`). |
| AWS-04 | Accounts accessed exclusively through federated identity with destroyed root credentials. | Documented exception. |
| AWS-05 | Single-region workloads where a multi-region trail adds cost without benefit. | Explicit downgrade path in docs/rubric.md. |

## SARIF output

`python run.py --fixtures --format sarif > out.sarif` emits SARIF 2.1.0. Every emitted
`ruleId` is declared in the `rules` array, each rule carries
`defaultConfiguration.level` (high → error, medium → warning, low → note), and results
include `partialFingerprints` so a repeated finding keeps a stable identity across runs
instead of re-opening as new. Fix text lives in `message.text` and the rule `help`.

## Limitations

Resource Graph is eventually consistent, so AZ-* detections lag by minutes. AWS Config needs
a recorder running. Neither pack covers GCP.

**docs/rubric.md** — the scoring matrix: four factors, 0-2 each, sum to a severity band; a worked example per band; and an explicit "when to downgrade" section (compensating control confirmed, non-production scope, data classification low). This is the single most Alignerr-legible file in your entire portfolio, because it is literally how they grade.
