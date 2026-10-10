"""
Termux-compatible DNS resolver module.
Provides safe DNS queries even when /etc/resolv.conf is not available.
"""

from typing import List, Optional
import dns.resolver
import dns.reversename


def get_resolver() -> dns.resolver.Resolver:
    """Return a configured dns.resolver.Resolver instance."""
    try:
        res = dns.resolver.Resolver()
    except Exception:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    # Ensure fallback nameservers if none detected
    if not res.nameservers:
        res.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    res.timeout = 3.0
    res.lifetime = 5.0
    return res


def resolve_records(domain: str, record_type: str) -> List[str]:
    """Resolve specific DNS record types (A, AAAA, MX, NS, TXT, CNAME, SOA)."""
    resolver = get_resolver()
    results = []
    try:
        answers = resolver.resolve(domain, record_type)
        for rdata in answers:
            if record_type == "MX":
                results.append(f"{rdata.exchange.to_text().rstrip('.')} (priority {rdata.preference})")
            elif record_type in ("NS", "CNAME"):
                results.append(rdata.target.to_text().rstrip("."))
            elif record_type == "TXT":
                # TXT records contain byte strings in strings attribute
                txt_strings = [part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part) for part in rdata.strings]
                results.append("".join(txt_strings))
            elif record_type == "SOA":
                results.append(
                    f"mname={rdata.mname.to_text().rstrip('.')} "
                    f"rname={rdata.rname.to_text().rstrip('.')} "
                    f"serial={rdata.serial}"
                )
            else:
                results.append(rdata.to_text().rstrip("."))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
        pass
    except Exception:
        pass
    return sorted(list(set(results)))


def reverse_dns(ip_address: str) -> Optional[str]:
    """Perform reverse DNS lookup (PTR record)."""
    resolver = get_resolver()
    try:
        rev_name = dns.reversename.from_address(ip_address)
        answers = resolver.resolve(rev_name, "PTR")
        if answers:
            return answers[0].to_text().rstrip(".")
    except Exception:
        return None
    return None
