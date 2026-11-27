"""Global blocklist: values hidden from the findings lists of every investigation (callbacks and embedded hosts,
attack sources). Nothing is deleted: findings.json keeps everything, and the lists show how many are hidden and
by which rule. Edited on the Settings page; stored in data/settings.json.

One entry per line, # starts a comment:
  example.org              the domain and its subdomains, as a host or inside a URL
  *.cdn.example  ns?.x.io  wildcards on the host
  203.0.113.0/24  10.1.2.3 addresses and networks (also inside URLs)
  =http://a                this exact value only
  re:^https?://[^/]*\\.local(/|$)   a regular expression on the whole value (case-insensitive)
Single-label names (a, http://a, foo:8080; not localhost or addresses) are hidden by a separate switch.
"""
import fnmatch
import ipaddress
import re
from urllib.parse import urlsplit

DEFAULT = """# XML, XSLT and schema namespaces quoted inside payloads (not contacted by the payload)
w3.org
apache.org
xmlsoap.org
schemas.microsoft.com
schemas.openxmlformats.org
purl.org
java.sun.com
xmlns.jcp.org
ns.adobe.com
json-schema.org
# documentation placeholders
example.com
example.org
example.net
"""


def host_of(value):
    s = str(value or "").strip().lower()
    if "://" in s:
        try:
            return (urlsplit(s).hostname or "").strip(".")
        except ValueError:
            return ""
    s = s.split("/")[0]
    if s.startswith("[") and "]" in s:                 # [::1]:80
        return s[1:s.index("]")]
    if s.count(":") == 1:                              # host:port (a bare IPv6 address has several colons)
        s = s.split(":")[0]
    return s.strip(".")


def _ip(h):
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


class Blocklist:
    def __init__(self, text="", single_label=True):
        self.single_label = bool(single_label)
        self.rules = []          # (kind, pattern, original line)
        self.errors = []
        for n, raw in enumerate(str(text or "").splitlines(), 1):
            line = raw.split(" #")[0].strip() if not raw.strip().startswith("re:") else raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if line.startswith("="):
                    self.rules.append(("exact", line[1:].strip().lower(), line))
                elif line.startswith("re:"):
                    self.rules.append(("re", re.compile(line[3:], re.I), line))
                elif "/" in line and _net(line):
                    self.rules.append(("net", _net(line), line))
                elif _ip(line):
                    self.rules.append(("net", ipaddress.ip_network(line), line))
                elif any(c in line for c in "*?["):
                    self.rules.append(("glob", line.lower(), line))
                else:
                    self.rules.append(("domain", line.lower().lstrip(".").rstrip("."), line))
            except (re.error, ValueError) as e:
                self.errors.append(f"line {n}: {line}: {e}")

    def match(self, value):
        """The rule that hides value, or None."""
        v = str(value or "").strip()
        lv = v.lower()
        h = host_of(v)
        ip = _ip(h)
        for kind, p, line in self.rules:
            if kind == "exact" and lv == p:
                return line
            if kind == "re" and p.search(v):
                return line
            if kind == "net" and ip is not None and ip.version == p.version and ip in p:
                return line
            if kind == "glob" and h and fnmatch.fnmatchcase(h, p):
                return line
            if kind == "domain" and h and (h == p or h.endswith("." + p)):
                return line
        if self.single_label and h and "." not in h and ip is None and h != "localhost":
            return "single-label name"
        return None

    def split(self, items, key="value"):
        """(kept, hidden) where hidden items carry the rule as 'rule'."""
        kept, hidden = [], []
        for it in items or []:
            r = self.match(it.get(key))
            if r:
                hidden.append({**it, "rule": r})
            else:
                kept.append(it)
        return kept, hidden


def _net(s):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def suggest(value):
    """A reasonable entry to block a value: the address, or the host's last two labels (three for co.uk-style)."""
    h = host_of(value)
    if not h:
        return "=" + str(value or "").strip()
    if _ip(h):
        return h
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def from_settings(s=None):
    import voyager_settings
    s = s or voyager_settings.load()
    return Blocklist(s.get("blocklist", DEFAULT), s.get("blocklist_single_label", True))


def filter_findings(f, bl):
    """Findings with blocked values moved out of 'sources' and 'callbacks' into 'hidden'."""
    if not f:
        return f
    out = dict(f)
    hidden = {}
    for k in ("sources", "callbacks"):
        out[k], hidden[k] = bl.split(f.get(k))
    out["hidden"] = hidden
    return out
