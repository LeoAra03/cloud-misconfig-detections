#!/usr/bin/env python3
"""cloud-misconfig-detections.

Detection pack for Azure and AWS cloud misconfigurations. Every detection ships
with a vulnerable fixture (fixtures/<id>/vulnerable.json) and a baseline fixture
(fixtures/<id>/baseline.json); this runner executes each detection against both
and asserts discrimination: it must fire on the vulnerable fixture and stay
silent on the baseline.

    python run.py --fixtures                 # full run: fire on vulnerable, silent on baseline
    python run.py --fixtures --format sarif > out.sarif
    python run.py --fixtures --expect-no-findings   # baseline-only negative run, must be clean

The KQL queries in azure/arg/, the Azure policy definitions in azure/policy/ and
the AWS Config rules in aws/config/ are the authoritative deployment artifacts.
The evaluators below reproduce their semantics against on-disk fixtures, so CI
can assert detection discrimination without a cloud account.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif-2.1.0/csprd01/schemas/"
    "sarif-schema-2.1.0.json"
)

LEVEL_SARIF = {"high": "error", "medium": "warning", "low": "note"}

RUBRIC_KEYS = ("exposure", "exploitability", "compensating", "data")


def rubric_band(score: int) -> str:
    if score <= 2:
        return "low"
    if score <= 5:
        return "medium"
    return "high"


@dataclass
class Finding:
    rule_id: str
    message: str
    severity: str
    variant: str
    resource_id: str
    location: dict | None = None
    key: str | None = None


@dataclass
class Detection:
    id: str
    cloud: str
    title: str
    severity: str
    description: str
    query: str
    query_path: str
    policy_path: str | None
    config_path: str | None
    rubric: dict[str, int]
    false_positive: str
    evaluate: Callable[[list[dict]], list[tuple[str, dict, str | None]]]

    def rubric_sum(self) -> int:
        return sum(self.rubric[key] for key in RUBRIC_KEYS)

    def rubric_string(self) -> str:
        return "+".join(str(self.rubric[key]) for key in RUBRIC_KEYS)


def fixture_path(detection_id: str, variant: str) -> Path:
    return ROOT / "fixtures" / detection_id / f"{variant}.json"


def load_fixture(detection_id: str, variant: str):
    path = fixture_path(detection_id, variant)
    with path.open() as handle:
        return json.load(handle), path.read_text()


def line_of(text: str, token: str) -> int | None:
    for index, line in enumerate(text.splitlines(), 1):
        if token in line:
            return index
    return None


def resource_identity(resource: dict) -> str:
    return (
        resource.get("id")
        or resource.get("resourceId")
        or resource.get("name")
        or resource.get("resourceType")
        or "?"
    )


# ---------------------------------------------------------------------------
# Evaluators: reproduce azure/arg/*.kql and aws/config/*.json semantics
# ---------------------------------------------------------------------------

ROLE_OWNER = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ROLE_CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
AUDIT_RELEVANT_TYPES = [
    "microsoft.storage/storageaccounts",
    "microsoft.keyvault/vaults",
    "microsoft.sql/servers",
    "microsoft.eventhub/namespaces",
]
AWS_MANAGED_ARN_PREFIX = "arn:aws:iam::aws:policy/"


def eval_az01(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Storage/storageAccounts":
            continue
        if resource.get("properties", {}).get("allowBlobPublicAccess") is True:
            findings.append(
                (
                    "Storage account '{}' allows public blob access "
                    "(allowBlobPublicAccess=true)".format(resource.get("name")),
                    resource,
                    "properties.allowBlobPublicAccess",
                )
            )
    return findings


def eval_az02(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Network/networkSecurityGroups":
            continue
        rules = resource.get("properties", {}).get("securityRules", []) or []
        for rule in rules:
            if rule.get("exempted"):
                continue  # documented exemption (jump-host NSGs)
            if rule.get("direction") != "Inbound" or rule.get("access") != "Allow":
                continue
            port = str(rule.get("destinationPortRange", ""))
            if port not in ("22", "3389"):
                continue
            sources = (
                [rule.get("sourceAddressPrefix")]
                if rule.get("sourceAddressPrefix")
                else list(rule.get("sourceAddressPrefixes") or [])
            )
            if "0.0.0.0/0" not in sources and "*" not in sources:
                continue
            findings.append(
                (
                    "NSG '{}' rule '{}' allows ingress from {} on TCP/{}".format(
                        resource.get("name"),
                        rule.get("name"),
                        sources[0] if sources else "*",
                        port,
                    ),
                    resource,
                    "properties.securityRules",
                )
            )
    return findings


def eval_az03(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Authorization/roleAssignments":
            continue
        props = resource.get("properties", {})
        if props.get("principalType") != "ServicePrincipal":
            continue
        role_def = (props.get("roleDefinitionId") or "").lower()
        if role_def.endswith(ROLE_OWNER.lower()):
            role = "Owner"
        elif role_def.endswith(ROLE_CONTRIBUTOR.lower()):
            role = "Contributor"
        else:
            continue
        scope = props.get("scope") or ""
        if not re.fullmatch(r"/subscriptions/[0-9a-fA-F\-]+$", scope):
            continue
        findings.append(
            (
                "Managed identity role assignment '{}' grants {} at subscription "
                "scope '{}'".format(resource.get("name"), role, scope),
                resource,
                "properties.scope",
            )
        )
    return findings


def eval_az04(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.KeyVault/vaults":
            continue
        if resource.get("properties", {}).get("enableSoftDelete") is False:
            findings.append(
                (
                    "Key vault '{}' has soft delete disabled "
                    "(enableSoftDelete=false)".format(resource.get("name")),
                    resource,
                    "properties.enableSoftDelete",
                )
            )
    return findings


def eval_az05(resources):
    findings = []
    for resource in resources:
        if resource.get("type", "").lower() not in AUDIT_RELEVANT_TYPES:
            continue
        settings = resource.get("properties", {}).get("diagnosticSettings")
        if not settings:
            findings.append(
                (
                    "Audit-relevant resource '{}' ({}) has no diagnostic setting".format(
                        resource.get("name"), resource.get("type")
                    ),
                    resource,
                    "properties.diagnosticSettings",
                )
            )
    return findings


def eval_az06(resources):
    by_id = {resource.get("id"): resource for resource in resources if resource.get("id")}
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Network/publicIPAddresses":
            continue
        address = (resource.get("properties") or {}).get("ipAddress")
        if not address:
            continue
        ipc = (resource.get("properties") or {}).get("ipConfiguration") or {}
        nic_id = ipc.get("id")
        nic = by_id.get(nic_id) if nic_id else None
        if nic is None:
            continue
        if (nic.get("properties") or {}).get("networkSecurityGroup"):
            continue
        findings.append(
            (
                "Public IP '{}' ({}) is attached to VM via NIC '{}' with no NSG "
                "association".format(resource.get("name"), address, nic.get("name")),
                resource,
                "properties.networkSecurityGroup",
            )
        )
    return findings


def eval_az07(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Web/sites":
            continue
        if resource.get("properties", {}).get("httpsOnly") is False:
            findings.append(
                (
                    "App Service '{}' does not enforce HTTPS "
                    "(httpsOnly=false)".format(resource.get("name")),
                    resource,
                    "properties.httpsOnly",
                )
            )
    return findings


def eval_az08(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Sql/servers":
            continue
        if resource.get("properties", {}).get("publicNetworkAccess") == "Enabled":
            findings.append(
                (
                    "SQL server '{}' has public network access enabled".format(
                        resource.get("name")
                    ),
                    resource,
                    "properties.publicNetworkAccess",
                )
            )
    return findings


def eval_az09(resources):
    findings = []
    for resource in resources:
        if resource.get("type") != "Microsoft.Compute/virtualMachines":
            continue
        disk = (
            resource.get("properties", {})
            .get("storageProfile", {})
            .get("osDisk", {})
            .get("managedDisk", {})
        )
        encryption_set = disk.get("diskEncryptionSet") or {}
        if not encryption_set.get("id"):
            findings.append(
                (
                    "VM '{}' has no disk encryption set on its OS disk".format(
                        resource.get("name")
                    ),
                    resource,
                    "properties.storageProfile.osDisk.managedDisk.diskEncryptionSet",
                )
            )
    return findings


def eval_aws01(resources):
    findings = []
    flags = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    for resource in resources:
        if resource.get("resourceType") != "AWS::S3::AccountPublicAccessBlock":
            continue
        config = resource.get("configuration", {}) or {}
        disabled = [flag for flag in flags if config.get(flag) is not True]
        if disabled:
            findings.append(
                (
                    "S3 Block Public Access partially disabled for {}: {} not enabled".format(
                        resource.get("resourceId"), ", ".join(disabled)
                    ),
                    resource,
                    None,
                )
            )
    return findings


def eval_aws02(resources):
    findings = []
    for resource in resources:
        if resource.get("resourceType") != "AWS::EC2::SecurityGroup":
            continue
        permissions = (
            (resource.get("configuration", {}) or {}).get("ipPermissions", []) or []
        )
        for permission in permissions:
            protocol = str(permission.get("ipProtocol", "")).lower()
            if protocol not in ("tcp", "-1", "all", ""):
                continue
            from_port = permission.get("fromPort")
            to_port = permission.get("toPort")

            def covers(port: int) -> bool:
                return (
                    from_port is None or to_port is None or from_port <= port <= to_port
                )

            if not (covers(22) or covers(3389)):
                continue
            for ip_range in permission.get("ipRanges", []) or []:
                if ip_range.get("cidrIp") in ("0.0.0.0/0", "*"):
                    findings.append(
                        (
                            "Security group '{}' allows {}/{}-{} to {}".format(
                                resource.get("resourceId"),
                                permission.get("ipProtocol") or "all",
                                from_port or "-",
                                to_port or "-",
                                ip_range.get("cidrIp"),
                            ),
                            resource,
                            "configuration.ipPermissions",
                        )
                    )
                    break
    return findings


def eval_aws03(resources):
    findings = []
    for resource in resources:
        if resource.get("resourceType") != "AWS::IAM::Policy":
            continue
        config = resource.get("configuration", {}) or {}
        arn = config.get("arn") or resource.get("resourceId") or ""
        if arn.startswith(AWS_MANAGED_ARN_PREFIX):
            continue  # AWS-managed policies cannot be edited by the customer
        statements = config.get("policyDocument", {}).get("Statement", []) or []
        for statement in statements:
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            targets = statement.get("Resource", [])
            if isinstance(targets, str):
                targets = [targets]
            if "*" in actions and "*" in targets:
                findings.append(
                    (
                        "IAM policy '{}' ({}) grants Action * on Resource * "
                        "(attachmentCount={})".format(
                            config.get("policyName"),
                            arn,
                            config.get("attachmentCount", 0),
                        ),
                        resource,
                        None,
                    )
                )
    return findings


def eval_aws04(resources):
    findings = []
    for resource in resources:
        if resource.get("resourceType") not in (
            "AWS::IAM::AccountSummary",
            "AWS::IAM::Account",
        ):
            continue
        config = resource.get("configuration", {}) or {}
        root = config.get("root", config)
        if root.get("mfaEnabled") is True:
            continue
        findings.append(
            (
                "AWS account root user has no MFA device enabled ({})".format(
                    resource.get("resourceId")
                ),
                resource,
                None,
            )
        )
    return findings


def eval_aws05(resources):
    findings = []
    for resource in resources:
        if resource.get("resourceType") != "AWS::CloudTrail::Trail":
            continue
        config = resource.get("configuration", {}) or {}
        if config.get("isMultiRegionTrail") is True:
            continue
        findings.append(
            (
                "CloudTrail trail '{}' is not a multi-region trail".format(
                    config.get("name") or resource.get("resourceId")
                ),
                resource,
                None,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def detection(
    id_: str,
    cloud: str,
    title: str,
    severity: str,
    description: str,
    query: str,
    evaluate,
    rubric: dict[str, int],
    false_positive: str,
) -> Detection:
    return Detection(
        id=id_,
        cloud=cloud,
        title=title,
        severity=severity,
        description=description,
        query=query,
        query_path=f"azure/arg/{id_}.kql" if cloud == "azure" else f"aws/config/{id_}.json",
        policy_path=f"azure/policy/{id_}.json" if cloud == "azure" else None,
        config_path=None if cloud == "azure" else f"aws/config/{id_}.json",
        rubric=rubric,
        false_positive=false_positive,
        evaluate=evaluate,
    )


REGISTRY: list[Detection] = [
    detection(
        "AZ-01",
        "azure",
        "Storage account allowBlobPublicAccess true",
        "high",
        "Storage accounts must not allow public blob access.",
        "Resources | where type == 'Microsoft.Storage/storageAccounts' | where properties.allowBlobPublicAccess == true",
        eval_az01,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "Static-site storage accounts intentionally allow public blob access; exclude by "
        "assignment scope rather than editing the rule.",
    ),
    detection(
        "AZ-02",
        "azure",
        "NSG rule 0.0.0.0/0 on 22 or 3389",
        "high",
        "Network security groups must not allow inbound SSH/RDP from 0.0.0.0/0.",
        "Resources | where type == 'Microsoft.Network/networkSecurityGroups' | mvexpand rule = properties.securityRules | where rule.direction == 'Inbound' ...",
        eval_az02,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "Jump-host NSGs where the broad source is intentional; the baseline fixture "
        "documents the exemption and the policy version uses exemptions rather than "
        "editing the rule.",
    ),
    detection(
        "AZ-03",
        "azure",
        "Managed identity with Owner or Contributor at subscription scope",
        "high",
        "Service principals must not be granted Owner or Contributor at subscription scope.",
        "Resources | where type == 'Microsoft.Authorization/roleassignments' | where properties.principalType == 'ServicePrincipal' ...",
        eval_az03,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "Break-glass service principals onboarded with Owner at subscription scope; "
        "treat as time-bound, documented exemptions.",
    ),
    detection(
        "AZ-04",
        "azure",
        "Key Vault enableSoftDelete false",
        "medium",
        "Key Vault vaults must have soft delete enabled.",
        "Resources | where type == 'Microsoft.KeyVault/vaults' | where properties.enableSoftDelete == false",
        eval_az04,
        {"exposure": 2, "exploitability": 1, "compensating": 0, "data": 2},
        "Vaults holding only ephemeral cache data where key recovery is not required.",
    ),
    detection(
        "AZ-05",
        "azure",
        "Diagnostic setting absent on a resource with an audit-relevant type",
        "medium",
        "Audit-relevant resources must have a diagnostic setting attached.",
        "Resources | where type in (audit-relevant types) | join ... diagnosticsettings | where diagnosticCount == 0",
        eval_az05,
        {"exposure": 1, "exploitability": 0, "compensating": 1, "data": 2},
        "Resources feeding non-audit pipelines whose diagnostic streams go elsewhere.",
    ),
    detection(
        "AZ-06",
        "azure",
        "Public IP attached to a VM with no NSG association",
        "high",
        "Public IP addresses must not sit in front of a VM whose NIC has no NSG.",
        "Resources | where type == 'Microsoft.Network/publicIPAddresses' | where isnotempty(properties.ipAddress) | join ... networkinterfaces ...",
        eval_az06,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 1},
        "VMs behind Azure Firewall — a deliberate miss; firewall presence is a separate "
        "detection, and one finding should carry one fact.",
    ),
    detection(
        "AZ-07",
        "azure",
        "App Service httpsOnly false",
        "medium",
        "App Service apps must enforce HTTPS.",
        "Resources | where type == 'Microsoft.Web/sites' | where properties.httpsOnly == false",
        eval_az07,
        {"exposure": 2, "exploitability": 1, "compensating": 1, "data": 1},
        "Internal-only apps behind a TLS-terminating front door where httpsOnly adds nothing.",
    ),
    detection(
        "AZ-08",
        "azure",
        "SQL server publicNetworkAccess enabled",
        "medium",
        "SQL servers must not expose public network access.",
        "Resources | where type == 'Microsoft.Sql/servers' | where properties.publicNetworkAccess == 'Enabled'",
        eval_az08,
        {"exposure": 2, "exploitability": 1, "compensating": 0, "data": 2},
        "SQL servers intentionally exposed for legacy app migration (time-bound).",
    ),
    detection(
        "AZ-09",
        "azure",
        "Disk encryption set absent",
        "low",
        "Virtual machine OS disks should use a customer-managed disk encryption set.",
        "Resources | where type == 'Microsoft.Compute/virtualMachines' | where ...managedDisk.diskEncryptionSet is absent",
        eval_az09,
        {"exposure": 0, "exploitability": 0, "compensating": 1, "data": 1},
        "Dev/test VMs where platform default encryption suffices; non-production scope.",
    ),
    detection(
        "AWS-01",
        "aws",
        "S3 Block Public Access partially disabled",
        "high",
        "S3 Block Public Access must be fully enabled at the account level.",
        "AWS Config rule AWS-01-s3-block-public-access-partially-disabled",
        eval_aws01,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "Sandbox accounts where public access is required by design (documented exemption).",
    ),
    detection(
        "AWS-02",
        "aws",
        "Security group ingress 0.0.0.0/0 on 22 or 3389",
        "high",
        "Security groups must not allow ingress SSH/RDP from 0.0.0.0/0.",
        "AWS Config rule AWS-02-restricted-ssh-rdp-ingress",
        eval_aws02,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "Bastion/jump security groups with broad SSH for incident access (exemption, not rule change).",
    ),
    detection(
        "AWS-03",
        "aws",
        "IAM policy action * on resource *",
        "high",
        "Customer-managed IAM policies must not grant Action * on Resource *.",
        "AWS Config rule AWS-03-iam-policy-star-on-star",
        eval_aws03,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "AWS-managed policies (arn:aws:iam::aws:policy/*) are filtered out — the customer cannot edit them.",
    ),
    detection(
        "AWS-04",
        "aws",
        "Root account without MFA",
        "high",
        "The AWS account root user must have an MFA device enabled.",
        "AWS Config rule AWS-04-root-account-mfa (periodic)",
        eval_aws04,
        {"exposure": 2, "exploitability": 2, "compensating": 0, "data": 2},
        "Accounts accessed exclusively through federated identity with destroyed root credentials.",
    ),
    detection(
        "AWS-05",
        "aws",
        "CloudTrail multi-region disabled",
        "medium",
        "CloudTrail trails must log all regions.",
        "AWS Config rule AWS-05-cloudtrail-multi-region-enabled",
        eval_aws05,
        {"exposure": 0, "exploitability": 0, "compensating": 1, "data": 2},
        "Single-region workloads where a multi-region trail adds cost without benefit (downgrade path).",
    ),
]


# ---------------------------------------------------------------------------
# Fixture evaluation and location helpers
# ---------------------------------------------------------------------------


def locate(text: str, resource: dict, key: str | None) -> dict:
    if key:
        leaf = key.split(".")[-1]
        line = line_of(text, '"{}"'.format(leaf))
        if line:
            source_line = text.splitlines()[line - 1]
            column = source_line.index('"{}"'.format(leaf)) + 1
            return {
                "uri": "",
                "startLine": line,
                "startColumn": column,
                "endLine": line,
                "endColumn": column + len(leaf) + 2,
            }
    rid = resource.get("id") or resource.get("resourceId") or resource.get("name")
    if rid:
        line = line_of(text, '"{}"'.format(rid)) or line_of(text, '"name"') or 1
    else:
        line = line_of(text, '"name"') or 1
    return {"uri": "", "startLine": line, "startColumn": 1, "endLine": line, "endColumn": 80}


def evaluate_detection(detection: Detection, variant: str) -> list[Finding]:
    fixture, text = load_fixture(detection.id, variant)
    resources = fixture.get("resources", []) or []
    findings = []
    for message, resource, key in detection.evaluate(resources):
        location = locate(text, resource, key)
        location["uri"] = "fixtures/{}/{}.json".format(detection.id, variant)
        findings.append(
            Finding(
                rule_id=detection.id,
                message=message,
                severity=detection.severity,
                variant=variant,
                resource_id=resource_identity(resource),
                location=location,
                key=key,
            )
        )
    return findings


def run_detection_pair(detection: Detection) -> tuple[list[Finding], list[Finding]]:
    return evaluate_detection(detection, "vulnerable"), evaluate_detection(detection, "baseline")


def run_full(detection_ids: list[str] | None = None):
    detections = [d for d in REGISTRY if not detection_ids or d.id in detection_ids]
    results: list[Finding] = []
    baseline_findings: dict[str, list[Finding]] = {}
    problems: list[str] = []
    for detection in detections:
        try:
            vulnerable, baseline = run_detection_pair(detection)
        except FileNotFoundError as exc:
            problems.append("{} : missing fixture ({})".format(detection.id, exc))
            baseline_findings[detection.id] = []
            continue
        baseline_findings[detection.id] = baseline
        if not vulnerable:
            problems.append(
                "{}: did not fire on vulnerable fixture "
                "(fixtures/{}/vulnerable.json)".format(detection.id, detection.id)
            )
        for finding in baseline:
            line = (
                finding.location["startLine"] if finding.location and finding.location.get("startLine") else "?"
            )
            problems.append(
                "{}: baseline fired on {} (fixtures/{}/baseline.json:{})".format(
                    detection.id, finding.resource_id, detection.id, line
                )
            )
        results.extend(vulnerable)
    return detections, results, baseline_findings, problems


def run_expect_no_findings(detection_ids: list[str] | None = None):
    detections = [d for d in REGISTRY if not detection_ids or d.id in detection_ids]
    results: list[Finding] = []
    problems: list[str] = []
    for detection in detections:
        try:
            _, baseline = run_detection_pair(detection)
        except FileNotFoundError as exc:
            problems.append("{} : missing fixture ({})".format(detection.id, exc))
            continue
        results.extend(baseline)
        if baseline:
            problems.append(
                "{}: baseline must be clean but fired {} finding(s)".format(
                    detection.id, len(baseline)
                )
            )
    return detections, results, problems


# ---------------------------------------------------------------------------
# Reporters
# ---------------------------------------------------------------------------


def emit_text(detections, results, baseline_findings, problems):
    lines = []
    for detection in detections:
        found = [f for f in results if f.rule_id == detection.id and f.variant == "vulnerable"]
        baseline = baseline_findings.get(detection.id, [])
        score = detection.rubric_sum()
        detail = ""
        if found:
            location = found[0].location
            at = "{}:{}".format(location["uri"], location["startLine"]) if location else found[0].resource_id
            detail = "fires on vulnerable: {} ({})".format(found[0].message, at)
        else:
            detail = "does NOT fire on vulnerable fixture"
        if baseline:
            detail += "; baseline FIRED (unexpected)"
        else:
            detail += "; baseline clean"
        lines.append(
            "{} [{}] {}: {} (rubric {}={} -> {})".format(
                detection.id,
                detection.cloud,
                detection.severity,
                detail,
                detection.rubric_string(),
                score,
                rubric_band(score),
            )
        )
    if problems:
        lines.append("")
        lines.append("Failures:")
        for problem in problems:
            lines.append("  - {}".format(problem))
    lines.append("")
    lines.append(
        "summary: {} detections, {} findings, {} failure(s)".format(
            len(detections), len(results), len(problems)
        )
    )
    print("\n".join(lines))


def emit_expect_no_findings(detections, results, problems):
    if problems:
        print("expect-no-findings: FAIL")
        for problem in problems:
            print("  - {}".format(problem))
    else:
        print("expect-no-findings: OK — {} baselines, 0 findings".format(len(detections)))


def build_sarif(detections, results):
    rules = []
    for index, detection in enumerate(detections):
        rules.append(
            {
                "id": detection.id,
                "name": detection.title,
                "shortDescription": {"text": detection.description},
                "fullDescription": {
                    "text": "{}\n\nKnown false positive: {}".format(
                        detection.description, detection.false_positive
                    )
                },
                "helpUri": "https://github.com/LeoAra03/cloud-misconfig-detections#detections",
                "defaultConfiguration": {"level": LEVEL_SARIF[detection.severity]},
                "properties": {
                    "cloud": detection.cloud,
                    "severity": detection.severity,
                    "rubric": detection.rubric,
                    "falsePositive": detection.false_positive,
                },
            }
        )
    sarif_results = []
    for finding in results:
        location = finding.location or {
            "uri": "fixtures/{}/vulnerable.json".format(finding.rule_id),
            "startLine": 1,
            "startColumn": 1,
            "endLine": 1,
            "endColumn": 1,
        }
        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": next(
                    i for i, d in enumerate(detections) if d.id == finding.rule_id
                ),
                "level": LEVEL_SARIF[finding.severity],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location["uri"]},
                            "region": {
                                "startLine": location["startLine"],
                                "startColumn": location["startColumn"],
                                "endLine": location["endLine"],
                                "endColumn": location["endColumn"],
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primary": hashlib.sha256(
                        "{}|{}|{}".format(
                            finding.rule_id, finding.resource_id, finding.variant
                        ).encode()
                    ).hexdigest()
                },
            }
        )
    declared = {rule["id"] for rule in rules}
    assert all(result["ruleId"] in declared for result in sarif_results)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cloud-misconfig-detections",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/LeoAra03/cloud-misconfig-detections",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="run.py",
        description="Run cloud misconfiguration detections against on-disk fixture pairs.",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Run detections against fixture pairs (default behavior).",
    )
    parser.add_argument(
        "--expect-no-findings",
        action="store_true",
        help="Baseline-only negative run; must be clean.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "sarif"),
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--detection",
        metavar="ID",
        help="Run only one detection, e.g. AZ-01.",
    )
    args = parser.parse_args(argv)

    detection_ids = [args.detection] if args.detection else None

    if args.expect_no_findings:
        detections, results, problems = run_expect_no_findings(detection_ids)
        if args.format == "sarif":
            print(json.dumps(build_sarif(detections, results), indent=2))
        else:
            emit_expect_no_findings(detections, results, problems)
        return 1 if problems else 0

    detections, results, baseline_findings, problems = run_full(detection_ids)
    if args.format == "sarif":
        print(json.dumps(build_sarif(detections, results), indent=2))
    else:
        emit_text(detections, results, baseline_findings, problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
