"""MX presence, null MX (RFC 7505) and mailbox-provider detection."""
from ..models import CheckResult

# (MX host suffix, SPF include for that provider). Verify against your provider's docs.
PROVIDERS = [
    ("aspmx.l.google.com", "Google Workspace", "include:_spf.google.com"),
    ("googlemail.com", "Google Workspace", "include:_spf.google.com"),
    ("mail.protection.outlook.com", "Microsoft 365", "include:spf.protection.outlook.com"),
    ("zoho.com", "Zoho Mail", "include:zoho.com"),
    ("zoho.eu", "Zoho Mail (EU)", "include:zoho.eu"),
    ("protonmail.ch", "Proton Mail", "include:_spf.protonmail.ch"),
    ("messagingengine.com", "Fastmail", "include:spf.messagingengine.com"),
    ("mail.icloud.com", "iCloud Mail", "include:icloud.com"),
]


def detect_provider(mx_hosts):
    for host in mx_hosts:
        for suffix, name, inc in PROVIDERS:
            if host == suffix or host.endswith("." + suffix):
                return name, inc
    return None, None


def check_mx(domain, resolver) -> CheckResult:
    res = CheckResult()
    ans = resolver.query(domain, "MX")
    hosts, null_mx = [], False
    for rec in ans.records:
        parts = rec.split()
        host = parts[-1].rstrip(".").lower() if parts else ""
        if host == "":
            null_mx = True
        else:
            hosts.append(host)
    provider, include = detect_provider(hosts)
    res.data = {"hosts": hosts, "null_mx": null_mx, "provider": provider, "provider_spf_include": include,
                "dns_status": ans.status}
    if ans.status == "error":
        res.add("mx", "info", "MX lookup failed", "DNS error while resolving MX; try again.", 0)
    elif null_mx:
        res.add("mx", "info", "Null MX published (RFC 7505)",
                "This domain says it receives no mail. Fine for a send-only subdomain if replies go to a "
                "Reply-To on another domain; otherwise replies will bounce.", 0)
    elif not hosts:
        res.add("mx", "medium", "No MX records",
                "Replies and bounces to this domain will fail, and many receivers distrust sender domains that "
                "cannot receive mail. Add MX records at your mailbox provider, or publish a null MX "
                "(0 .) if the domain is deliberately send-only.", 10)
    else:
        res.add("mx", "pass", f"{len(hosts)} MX record(s)" + (f" ({provider})" if provider else ""),
                ", ".join(hosts), 0)
    return res
