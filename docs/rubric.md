# Severity rubric

Each detection severity is derived from four factors, scored 0–2 by two reviewers
independently. The reviewers' scores must land within one band; the factor scores — not a
feeling — derive the severity. The scores for every detection are recorded in `run.py`
(REGISTRY) and printed by `python run.py --fixtures`.

## The four factors

| Factor | 0 | 1 | 2 |
|---|---|---|---|
| Exposure | Internal-only; not reachable outside the subscription or VPC | Reachable from other tenants or peered networks | Internet-reachable |
| Exploitability without credentials | Requires valid credentials or local/privileged access | Credentialed attack path, or dependent on social engineering | Unauthenticated remote exploitation |
| Compensating control present elsewhere | Strong compensating control (WAF, firewall, separate detection) | Partial or optional compensating control | No compensating control |
| Data sensitivity at the default configuration | Public or non-sensitive | Internal business data | Regulated or customer data |

## Severity bands

| Sum | Band | SARIF `defaultConfiguration.level` |
|---|---|---|
| 0–2 | low | note |
| 3–5 | medium | warning |
| 6–8 | high | error |

## Worked examples

### Low — AZ-09: Disk encryption set absent (sum 2)

- Exposure 0: OS disk encryption is not internet-reachable.
- Exploitability 0: requires compromise of the host or the storage fabric.
- Compensating 1: platform default encryption at rest is already enabled.
- Data 1: dev/test workload, no regulated data.

Sum 2 → low.

### Medium — AZ-04: Key Vault `enableSoftDelete` false (sum 5)

- Exposure 2: Key Vault control plane is internet-reachable.
- Exploitability 1: destroying keys requires authenticated credentials.
- Compensating 0: with soft delete off, there is no built-in recovery window.
- Data 2: vaults hold keys and secrets by default.

Sum 5 → medium.

### High — AZ-01: Storage account `allowBlobPublicAccess` true (sum 8)

- Exposure 2: the blob endpoint is internet-reachable.
- Exploitability 2: anonymous read requires no credentials.
- Compensating 0: no compensating control at the default configuration.
- Data 2: the default configuration may hold customer or regulated data.

Sum 8 → high.

## When to downgrade

A finding may be downgraded at most one band, and only when the reason is documented:

- Compensating control confirmed and effective (for example, a WAF in front of an exposed
  storage endpoint).
- Non-production scope (dev/test labels, sandbox subscriptions).
- Data classification confirmed low or public.

Never downgrade a finding that is both internet-reachable and exploitable without
credentials below medium.
