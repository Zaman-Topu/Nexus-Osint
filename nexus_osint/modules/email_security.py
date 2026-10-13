"""
SPF / DMARC Mail Security Posture & Spoofability Analyzer for NexusOSINT.
Analyzes email authentication records, DMARC policies, SPF enforcement mechanisms,
and computes spoofability risk vectors.
"""

from typing import Any, Dict, List, Optional
from nexus_osint.resolver import resolve_records


def parse_dmarc_record(dmarc_raw: str) -> Dict[str, str]:
    """Parse DMARC semicolon-delimited tags into key-value pairs."""
    tags: Dict[str, str] = {}
    parts = dmarc_raw.split(";")
    for part in parts:
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    return tags


def analyze_mail_security_posture(domain: str) -> Dict[str, Any]:
    """
    Perform deep analysis of SPF and DMARC mail authentication records
    to determine spoofability posture and phishing resistance.
    """
    clean_domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]

    # 1. Fetch SPF records
    txt_records = resolve_records(clean_domain, "TXT")
    spf_records = [r for r in txt_records if "v=spf1" in r]

    # 2. Fetch DMARC records (with RFC 7489 organizational domain fallback)
    dmarc_records = resolve_records(f"_dmarc.{clean_domain}", "TXT")
    dmarc_record = dmarc_records[0] if dmarc_records else None
    inherited_from = None

    if not dmarc_record and clean_domain.count(".") >= 2:
        parent_domain = ".".join(clean_domain.split(".")[1:])
        parent_dmarc = resolve_records(f"_dmarc.{parent_domain}", "TXT")
        if parent_dmarc:
            dmarc_record = parent_dmarc[0]
            inherited_from = parent_domain

    # Parse SPF details
    has_spf = len(spf_records) > 0
    multi_spf_error = len(spf_records) > 1
    spf_qualifier = "None"
    spf_mechanisms = []
    if has_spf:
        spf_str = spf_records[0]
        tokens = spf_str.split()
        for token in tokens:
            if token.endswith("all"):
                spf_qualifier = token
            elif token.startswith(("include:", "ip4:", "ip6:", "a", "mx", "ptr", "exists:")):
                spf_mechanisms.append(token)

    # Parse DMARC details
    has_dmarc = dmarc_record is not None
    dmarc_tags = parse_dmarc_record(dmarc_record) if dmarc_record else {}
    dmarc_sub_policy = dmarc_tags.get("sp")

    # If inherited from organizational parent, RFC 7489 mandates using sp if defined, else p
    if inherited_from and dmarc_sub_policy:
        dmarc_policy = dmarc_sub_policy
    else:
        dmarc_policy = dmarc_tags.get("p", "none" if has_dmarc else "missing")

    pct_val = dmarc_tags.get("pct", "100")
    rua = dmarc_tags.get("rua", "None")

    # Evaluate Spoofability Posture
    spoofable = False
    risk_level = "LOW"
    posture = "SECURE"
    explanation = ""

    if not has_spf and not has_dmarc:
        spoofable = True
        risk_level = "CRITICAL"
        posture = "CRITICAL: Highly Spoofable (No SPF or DMARC)"
        explanation = (
            "Domain has zero email authentication records. "
            "Threat actors can trivially forge emails from this domain with guaranteed inbox delivery."
        )
    elif multi_spf_error:
        spoofable = True
        risk_level = "HIGH"
        posture = "HIGH RISK: Multiple SPF Records (RFC 7208 PermError)"
        explanation = (
            f"Domain publishes {len(spf_records)} SPF records. RFC 7208 mandates a PermError when multiple SPF records "
            "are found, causing receiving mail servers to fail authentication and leaving inboxes vulnerable."
        )
    elif not has_dmarc:
        spoofable = True
        risk_level = "HIGH"
        posture = "HIGH RISK: Spoofable (Missing DMARC Policy)"
        explanation = (
            "SPF is configured, but missing DMARC enforcement allows attackers to forge "
            "the RFC5322 From: header without detection in most client inboxes."
        )
    elif dmarc_policy == "none":
        spoofable = True
        risk_level = "MEDIUM"
        posture = "WARNING: Spoofable (DMARC Policy is 'none' / Monitoring Only)"
        explanation = (
            "DMARC policy is set to 'p=none'. Unauthorized spoofed emails will generate telemetry "
            "reports but will NOT be blocked or quarantined by receiving mail servers."
        )
    elif pct_val == "0":
        spoofable = True
        risk_level = "MEDIUM"
        posture = f"WARNING: Spoofable (DMARC pct=0 Disables Enforcement)"
        explanation = (
            f"DMARC policy is set to '{dmarc_policy}', but 'pct=0' instructs receivers to apply the policy "
            "to 0% of mail, effectively disabling filtering."
        )
    elif dmarc_policy == "quarantine":
        try:
            pct_int = int(pct_val)
        except ValueError:
            pct_int = 100
        spoofable = pct_int < 100
        risk_level = "MEDIUM" if spoofable else "LOW"
        posture = (
            f"MODERATE: Partially Protected (DMARC Quarantine Enforced for {pct_val}%)"
            if pct_int < 100
            else "MODERATE: Partially Protected (DMARC Quarantine Enforced)"
        )
        explanation = (
            "DMARC policy is set to 'p=quarantine'. Spoofed emails are diverted to the recipient's "
            "Spam or Junk folder rather than rejected outright."
        )
    elif dmarc_policy == "reject":
        try:
            pct_int = int(pct_val)
        except ValueError:
            pct_int = 100
        spoofable = pct_int < 100
        risk_level = "MEDIUM" if spoofable else "SECURE"
        posture = (
            f"MODERATE: Partial Reject (DMARC Reject Enforced for {pct_val}%)"
            if pct_int < 100
            else "SECURE: Strictly Protected (DMARC Reject Enforced)"
        )
        explanation = (
            "DMARC policy is set to 'p=reject'. Unauthorized emails will be rejected by compliant mail servers, "
            "providing robust anti-spoofing and anti-phishing defense."
        )

    if inherited_from:
        explanation += f" (Note: DMARC policy inherited from organizational domain '{inherited_from}' per RFC 7489)."

    return {
        "domain": clean_domain,
        "has_spf": has_spf,
        "spf_records": spf_records,
        "spf_qualifier": spf_qualifier,
        "spf_mechanisms": spf_mechanisms,
        "has_dmarc": has_dmarc,
        "dmarc_record": dmarc_record,
        "dmarc_policy": dmarc_policy,
        "dmarc_subdomain_policy": dmarc_sub_policy,
        "dmarc_percentage": pct_val,
        "dmarc_reporting_rua": rua,
        "spoofable": spoofable,
        "risk_level": risk_level,
        "posture": posture,
        "assessment": explanation,
    }
