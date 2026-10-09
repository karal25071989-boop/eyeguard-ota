#!/usr/bin/env python3
"""EyeGuard weekly adult-domain discovery (read-only).

Downloads pinned public blocklists, verifies them, compares them with the live
signed EyeGuard OTA list using the Android parent-label rule, applies the
Dataset Builder safety checks and writes review reports.

This tool never writes to the repository, never signs anything and never
publishes. Its only outputs are files in --out.

Python 3 standard library only.
"""

import argparse
import base64
import csv
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TOOL_VERSION = "1.0.0"
HERE = os.path.dirname(os.path.abspath(__file__))

EXIT_OK = 0
EXIT_VALIDATION = 2
EXIT_USAGE = 3


class DiscoveryError(Exception):
    """A validation failure. The run must stop and publish no candidates."""

    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Hostname rules. Port of Android SiteShieldHostNormalize and the Dataset
# Builder HostNormalize (identical behaviour for bare hostnames).
# ---------------------------------------------------------------------------

MAX_RAW_LEN = 2048
MAX_DOMAIN_LEN = 253
MAX_LABEL_LEN = 63
_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_LDH = re.compile(r"^[a-z0-9.-]+$")


def _trim_dots(value):
    return value.strip(".")


def _authority_host(with_scheme):
    rest = with_scheme.split("://", 1)[1] if "://" in with_scheme else ""
    if not rest:
        return None
    for sep in ("/", "?", "#"):
        rest = rest.split(sep, 1)[0]
    host_port = rest.rsplit("@", 1)[-1]
    if host_port.startswith("["):
        end = host_port.find("]")
        if end <= 1:
            return None
        return host_port[1:end]
    return host_port.split(":", 1)[0] or None


def normalize_host(raw):
    """Return the canonical EyeGuard hostname, or None if invalid."""
    if raw is None:
        return None
    trimmed = raw.strip()
    if not trimmed or len(trimmed) > MAX_RAW_LEN:
        return None
    if any(c in trimmed for c in (" ", "\n", "\t", "\r")):
        return None
    lower = trimmed.lower()
    if lower.startswith("javascript:") or lower.startswith("data:"):
        return None
    with_scheme = trimmed if "://" in trimmed else "https://" + trimmed
    host = _authority_host(with_scheme)
    if host is None:
        return None
    host = _trim_dots(host.lower())
    if not host:
        return None
    if ":" in host or _IPV4.match(host):
        return None
    if host == "localhost" or host.endswith(".localhost"):
        return None
    try:
        if host.isascii():
            ascii_host = host
        else:
            ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    ascii_host = _trim_dots(ascii_host.lower())
    while ascii_host.startswith("www."):
        ascii_host = ascii_host[4:]
    if not ascii_host or "." not in ascii_host:
        return None
    if len(ascii_host) > MAX_DOMAIN_LEN:
        return None
    if not _LDH.match(ascii_host):
        return None
    for label in ascii_host.split("."):
        if not label or len(label) > MAX_LABEL_LEN:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
    return ascii_host


def listed_cover(host, listed):
    """Android SiteShieldDomainMatch: exact host, then parents that still
    contain a dot. Never matches a single-label TLD. Returns the listed entry."""
    if not host or not listed:
        return None
    current = host
    while True:
        if current in listed:
            return current
        dot = current.find(".")
        if dot < 0:
            return None
        current = current[dot + 1:]
        if "." not in current:
            return None


def strict_parent_cover(host, listed):
    """Like listed_cover but ignores the host itself."""
    dot = host.find(".")
    if dot < 0:
        return None
    parent = host[dot + 1:]
    if "." not in parent:
        return None
    return listed_cover(parent, listed)


def captures_any(host, listed):
    """Entries in `listed` that `host` would block via the parent-label walk
    (entries equal to or under `host`)."""
    suffix = "." + host
    return sorted(d for d in listed if d == host or d.endswith(suffix))


# ---------------------------------------------------------------------------
# Public Suffix List. Port of the Dataset Builder PublicSuffixList.
# ---------------------------------------------------------------------------


class PublicSuffixList:
    def __init__(self, text):
        self.rules = set()
        self.exceptions = set()
        self.wildcards = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                self.exceptions.add(line[1:].lower())
            elif line.startswith("*."):
                self.wildcards.add(line[2:].lower())
            else:
                self.rules.add(line.lower())

    def suffix_label_count(self, host):
        labels = host.split(".")
        n = len(labels)
        for i in range(n):
            if ".".join(labels[i:]) in self.exceptions:
                return n - i - 1
        for i in range(n):
            if ".".join(labels[i:]) in self.rules:
                return n - i
            if i + 1 < n and ".".join(labels[i + 1:]) in self.wildcards:
                return n - i
        return 1

    def is_public_suffix(self, host):
        return self.suffix_label_count(host) == len(host.split("."))

    def registrable_domain(self, host):
        if not host:
            return None
        labels = host.split(".")
        count = self.suffix_label_count(host)
        if count <= 0 or len(labels) <= count:
            return None
        return ".".join(labels[len(labels) - (count + 1):])


# ---------------------------------------------------------------------------
# ECDSA P-256 / SHA-256 signature verification (verify only, public data).
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_A = _P - 3
_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)
_SPKI_P256_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
)


def _on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _scalar_mult(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _der_read(data, pos, expected_tag):
    if pos >= len(data) or data[pos] != expected_tag:
        raise ValueError("der_tag")
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 2:
            raise ValueError("der_length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise ValueError("der_truncated")
    return data[pos:end], end


def parse_der_signature(sig):
    body, end = _der_read(sig, 0, 0x30)
    if end != len(sig):
        raise ValueError("der_trailing")
    r_bytes, pos = _der_read(body, 0, 0x02)
    s_bytes, pos = _der_read(body, pos, 0x02)
    if pos != len(body):
        raise ValueError("der_trailing_body")
    return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big")


def parse_spki_p256(spki_der):
    if len(spki_der) != 91 or not spki_der.startswith(_SPKI_P256_PREFIX):
        raise ValueError("not_p256_spki")
    point = spki_der[len(_SPKI_P256_PREFIX):]
    if point[0] != 0x04:
        raise ValueError("not_uncompressed_point")
    q = (int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:65], "big"))
    if not _on_curve(q):
        raise ValueError("point_not_on_curve")
    return q


def ecdsa_p256_verify(public_key_spki_der, message, der_signature):
    try:
        q = parse_spki_p256(public_key_spki_der)
        r, s = parse_der_signature(der_signature)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < _N and 1 <= s < _N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, _N)
    point = _point_add(_scalar_mult(e * w % _N, _G), _scalar_mult(r * w % _N, q))
    if point is None:
        return False
    return point[0] % _N == r


# ---------------------------------------------------------------------------
# Network access: HTTPS only, allow-listed hosts, size caps, retries.
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect_refused", headers, fp)


class Fetcher:
    def __init__(self, allowed_hosts, timeout, retries, token=None):
        self.allowed_hosts = set(allowed_hosts)
        self.timeout = timeout
        self.retries = max(1, retries)
        self.token = token
        self._opener = urllib.request.build_opener(_NoRedirect())

    def check_url(self, url):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https":
            raise DiscoveryError("URL_NOT_HTTPS", url)
        if parts.hostname not in self.allowed_hosts or parts.port not in (None, 443):
            raise DiscoveryError("URL_HOST_NOT_ALLOWED", url)

    def get(self, url, max_bytes, accept=None):
        self.check_url(url)
        last = None
        for attempt in range(self.retries):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": f"eyeguard-discovery/{TOOL_VERSION}"})
                if accept:
                    req.add_header("Accept", accept)
                if self.token and urllib.parse.urlsplit(url).hostname == "api.github.com":
                    req.add_header("Authorization", f"Bearer {self.token}")
                with self._opener.open(req, timeout=self.timeout) as resp:
                    declared = resp.headers.get("Content-Length")
                    if declared and declared.isdigit() and int(declared) > max_bytes:
                        raise DiscoveryError("DOWNLOAD_TOO_LARGE", f"{url} declares {declared} > {max_bytes}")
                    data = resp.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        raise DiscoveryError("DOWNLOAD_TOO_LARGE", f"{url} exceeds {max_bytes} bytes")
                    return data
            except DiscoveryError:
                raise
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
                if isinstance(exc, urllib.error.HTTPError) and exc.code in (301, 302, 303, 307, 308, 401, 403, 404):
                    break
                time.sleep(2 ** attempt)
        raise DiscoveryError("DOWNLOAD_FAILED", f"{url}: {last}")

    def get_json(self, url, max_bytes=1048576):
        raw = self.get(url, max_bytes, accept="application/vnd.github+json")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DiscoveryError("BAD_JSON", f"{url}: {exc}")


# ---------------------------------------------------------------------------
# Source download, integrity and parsing.
# ---------------------------------------------------------------------------

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HOSTS_BOILERPLATE = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
}


def git_blob_sha1(data):
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def resolve_pin(fetcher, src):
    q = urllib.parse.urlencode({"path": src["path"], "sha": src["branch"], "per_page": 1})
    url = f"https://api.github.com/repos/{src['owner']}/{src['repo']}/commits?{q}"
    commits = fetcher.get_json(url)
    if not isinstance(commits, list) or not commits:
        raise DiscoveryError("PIN_UNRESOLVED", f"{src['id']}: no commit for {src['path']}")
    sha = str(commits[0].get("sha", ""))
    if not _HEX40.match(sha):
        raise DiscoveryError("PIN_INVALID", f"{src['id']}: {sha!r}")
    date = commits[0].get("commit", {}).get("committer", {}).get("date", "")
    return sha, date


def expected_blob(fetcher, src, commit):
    q = urllib.parse.urlencode({"ref": commit})
    path = urllib.parse.quote(src["path"])
    url = f"https://api.github.com/repos/{src['owner']}/{src['repo']}/contents/{path}?{q}"
    meta = fetcher.get_json(url)
    blob = str(meta.get("sha", "")) if isinstance(meta, dict) else ""
    size = meta.get("size") if isinstance(meta, dict) else None
    if not _HEX40.match(blob) or not isinstance(size, int):
        raise DiscoveryError("BLOB_META_INVALID", f"{src['id']}: {meta!r:.200}")
    return blob, size


def parse_source(src, data, max_malformed_ratio):
    """Parse and validate one downloaded list. Returns (entries, stats)."""
    if b"\x00" in data:
        raise DiscoveryError("SOURCE_BINARY", f"{src['id']}: NUL byte in text")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DiscoveryError("SOURCE_NOT_UTF8", f"{src['id']}: {exc}")
    lines = text.splitlines()
    header = [ln.strip() for ln in lines if ln.lstrip().startswith("#")]
    for expected in src["expected_header_lines"]:
        if expected not in header:
            raise DiscoveryError("SOURCE_HEADER_MISSING", f"{src['id']}: missing {expected!r}")
    count_re = re.compile(src["count_header_regex"])
    declared = None
    for ln in header:
        m = count_re.match(ln)
        if m:
            declared = int(m.group(1).replace(",", ""))
            break
    if declared is None:
        raise DiscoveryError("SOURCE_COUNT_HEADER_MISSING", src["id"])

    entries = []
    malformed = 0
    boilerplate = 0
    data_lines = 0
    for ln in lines:
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        data_lines += 1
        body = stripped.split("#", 1)[0].strip()
        if src["format"] == "domains":
            if not body or any(c.isspace() for c in body):
                malformed += 1
                continue
            entries.append(body)
        elif src["format"] == "hosts":
            parts = body.split()
            if len(parts) != 2:
                malformed += 1
                continue
            ip, host = parts
            if host.lower() in _HOSTS_BOILERPLATE:
                boilerplate += 1
                continue
            if ip != "0.0.0.0":
                malformed += 1
                continue
            entries.append(host)
        else:
            raise DiscoveryError("SOURCE_FORMAT_UNKNOWN", src["format"])

    if data_lines and malformed / data_lines > max_malformed_ratio:
        raise DiscoveryError("SOURCE_TOO_MANY_MALFORMED", f"{src['id']}: {malformed}/{data_lines}")
    if len(entries) != declared:
        raise DiscoveryError("SOURCE_COUNT_MISMATCH", f"{src['id']}: header {declared}, parsed {len(entries)}")
    if not (src["min_entries"] <= len(entries) <= src["max_entries"]):
        raise DiscoveryError("SOURCE_COUNT_OUT_OF_BOUNDS", f"{src['id']}: {len(entries)}")

    normalized = {}
    invalid = 0
    for raw in entries:
        host = normalize_host(raw)
        if host is None:
            invalid += 1
            continue
        normalized.setdefault(host, raw)
    stats = {
        "declared_count": declared,
        "parsed_entries": len(entries),
        "malformed_lines": malformed,
        "boilerplate_lines": boilerplate,
        "invalid_hostnames": invalid,
        "unique_normalized_hosts": len(normalized),
        "header": [h for h in header if h.startswith(("# Title", "# Version", "# Last modified", "# Date", "# Number"))],
    }
    return normalized, stats


def download_source(fetcher, src, pin, max_malformed_ratio):
    if pin:
        if not _HEX40.match(pin):
            raise DiscoveryError("PIN_INVALID", f"{src['id']}: {pin!r}")
        commit, commit_date = pin, ""
    else:
        commit, commit_date = resolve_pin(fetcher, src)
    blob, size = expected_blob(fetcher, src, commit)
    if size > src["max_bytes"]:
        raise DiscoveryError("SOURCE_TOO_LARGE", f"{src['id']}: {size}")
    url = f"https://raw.githubusercontent.com/{src['owner']}/{src['repo']}/{commit}/{src['path']}"
    data = fetcher.get(url, src["max_bytes"])
    if len(data) != size:
        raise DiscoveryError("SOURCE_SIZE_MISMATCH", f"{src['id']}: got {len(data)}, expected {size}")
    actual_blob = git_blob_sha1(data)
    if actual_blob != blob:
        raise DiscoveryError("SOURCE_BLOB_MISMATCH", f"{src['id']}: got {actual_blob}, expected {blob}")
    hosts, stats = parse_source(src, data, max_malformed_ratio)
    meta = {
        "id": src["id"],
        "name": src["name"],
        "repository": f"https://github.com/{src['owner']}/{src['repo']}",
        "path": src["path"],
        "license": src["license"],
        "informational_only": bool(src.get("informational_only")),
        "commit": commit,
        "commit_date": commit_date,
        "url": url,
        "bytes": len(data),
        "git_blob_sha1": actual_blob,
        "sha256": hashlib.sha256(data).hexdigest(),
        **stats,
    }
    return hosts, meta


# ---------------------------------------------------------------------------
# Live OTA list.
# ---------------------------------------------------------------------------


def load_live_ota(fetcher, cfg, public_key_der):
    live = cfg["live_ota"]
    manifest_bytes = fetcher.get(live["manifest_url"], live["manifest_max_bytes"])
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryError("LIVE_MANIFEST_INVALID", str(exc))
    for key in ("domainsUrl", "snapshotUrl", "signatureAlgorithm", "signatureBase64", "sha256Gzip", "preparedAtEpochMs"):
        if key not in manifest:
            raise DiscoveryError("LIVE_MANIFEST_INVALID", f"missing {key}")
    if manifest["signatureAlgorithm"] != live["signature_algorithm"]:
        raise DiscoveryError("LIVE_SIGNATURE_ALGORITHM", manifest["signatureAlgorithm"])
    snapshot_bytes = fetcher.get(manifest["snapshotUrl"], live["snapshot_max_bytes"])
    domains_gz = fetcher.get(manifest["domainsUrl"], live["domains_max_bytes"])
    try:
        snapshot = json.loads(snapshot_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryError("LIVE_SNAPSHOT_INVALID", str(exc))

    gz_sha = hashlib.sha256(domains_gz).hexdigest()
    if gz_sha != str(manifest["sha256Gzip"]).lower():
        raise DiscoveryError("LIVE_HASH_MISMATCH", "domains.bin vs manifest.sha256Gzip")
    if gz_sha != str(snapshot.get("sha256Gzip", "")).lower():
        raise DiscoveryError("LIVE_HASH_MISMATCH", "domains.bin vs snapshot.sha256Gzip")
    try:
        signature = base64.b64decode(manifest["signatureBase64"], validate=True)
    except (ValueError, TypeError):
        raise DiscoveryError("LIVE_SIGNATURE_INVALID", "signature is not base64")
    if not ecdsa_p256_verify(public_key_der, domains_gz, signature):
        raise DiscoveryError("LIVE_SIGNATURE_INVALID", "ECDSA P-256 verification failed")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(domains_gz)) as gz:
            plain = gz.read(live["uncompressed_max_bytes"] + 1)
    except (OSError, EOFError) as exc:
        raise DiscoveryError("LIVE_GZIP_INVALID", str(exc))
    if len(plain) > live["uncompressed_max_bytes"]:
        raise DiscoveryError("LIVE_TOO_LARGE", "uncompressed list exceeds cap")
    if hashlib.sha256(plain).hexdigest() != str(snapshot.get("sha256Uncompressed", "")).lower():
        raise DiscoveryError("LIVE_HASH_MISMATCH", "uncompressed vs snapshot.sha256Uncompressed")
    domains = {ln.strip() for ln in plain.decode("utf-8").splitlines() if ln.strip()}
    if len(domains) != int(snapshot.get("recordCount", -1)):
        raise DiscoveryError("LIVE_COUNT_MISMATCH", f"{len(domains)} vs recordCount {snapshot.get('recordCount')}")
    meta = {
        "manifest_url": live["manifest_url"],
        "package_version": snapshot.get("eyeguardPackageVersion", ""),
        "prepared_at_epoch_ms": manifest["preparedAtEpochMs"],
        "record_count": len(domains),
        "sha256_gzip": gz_sha,
        "signature_verified": True,
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
    }
    return domains, meta


def live_fingerprint(fetcher, cfg):
    live = cfg["live_ota"]
    manifest_bytes = fetcher.get(live["manifest_url"], live["manifest_max_bytes"])
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    snapshot_bytes = fetcher.get(manifest["snapshotUrl"], live["snapshot_max_bytes"])
    domains_gz = fetcher.get(manifest["domainsUrl"], live["domains_max_bytes"])
    return {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "snapshot_sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        "sha256_gzip": hashlib.sha256(domains_gz).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Safety data (copies of the Dataset Builder's public-safe files).
# ---------------------------------------------------------------------------

OFFICIAL_SUFFIXES = (
    ".gov", ".edu", ".mil", ".int",
    ".gov.in", ".nic.in", ".ac.in", ".edu.in", ".res.in", ".ernet.in",
    ".gov.uk", ".ac.uk", ".gov.au", ".edu.au", ".govt.nz", ".ac.nz",
    ".gouv.fr", ".gob.mx", ".gob.es", ".go.jp", ".ac.jp", ".go.kr", ".ac.kr",
    ".gov.br", ".gc.ca", ".gov.sg", ".gov.za", ".ac.za", ".gov.cn", ".edu.cn",
    ".ac.id", ".ac.th", ".ac.be", ".ac.at", ".ac.il", ".gov.ie", ".gov.hk",
    ".gov.de", ".bund.de", ".gov.it", ".gov.pl", ".gov.nl",
    ".gov.ar", ".gob.ar", ".gov.co", ".gov.cl", ".gov.ph", ".gov.my",
    ".gov.pk", ".gov.bd", ".gov.lk", ".gov.np",
)


def official_suffix(domain):
    return any(domain == s[1:] or domain.endswith(s) for s in OFFICIAL_SUFFIXES)


def _read_text(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def load_csv_domains(path, column):
    out = set()
    with open(path, "r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            host = normalize_host(row.get(column, ""))
            if host:
                out.add(host)
    return out


def load_line_domains(path):
    out = set()
    for line in _read_text(path).splitlines():
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        host = normalize_host(t)
        if host:
            out.add(host)
    return out


class SafetyData:
    def __init__(self, base_dir):
        safety = os.path.join(base_dir, "safety")
        self.allowlist = load_csv_domains(os.path.join(safety, "allowlist.csv"), "domain")
        self.canaries = load_csv_domains(os.path.join(safety, "critical_canaries.csv"), "domain")
        self.legitimate = load_line_domains(os.path.join(safety, "legitimate_control_corpus.txt"))
        self.shared_platforms = load_line_domains(os.path.join(base_dir, "shared_platforms.txt"))
        self.psl = PublicSuffixList(_read_text(os.path.join(safety, "public_suffix_list.dat")))
        if not self.allowlist or not self.canaries or not self.legitimate:
            raise DiscoveryError("SAFETY_DATA_MISSING", "allowlist, canaries and corpus must be non-empty")
        if len(self.psl.rules) < 1000:
            raise DiscoveryError("SAFETY_DATA_MISSING", "public suffix list looks truncated")


# ---------------------------------------------------------------------------
# Classification.
# ---------------------------------------------------------------------------

BLOCKED_CODES = (
    "PUBLIC_SUFFIX", "NO_REGISTRABLE", "OFFICIAL_SUFFIX", "CANARY_COLLISION",
    "ALLOWLIST_EXACT", "ALLOWLIST_CAPTURE", "LEGIT_CAPTURE", "SHARED_PLATFORM_ROOT",
)
REVIEW_CODES = ("ALLOWLIST_CHILD", "LEGIT_CORPUS", "SHARED_PLATFORM", "SCOPE_WIDENS")
TIER_ORDER = {"A": 0, "B": 1, "C": 2, "R": 3, "X": 4}


def safety_codes(host, registrable, safety):
    codes = []
    if safety.psl.is_public_suffix(host):
        codes.append("PUBLIC_SUFFIX")
    elif registrable is None:
        codes.append("NO_REGISTRABLE")
    if official_suffix(host):
        codes.append("OFFICIAL_SUFFIX")
    if listed_cover(host, safety.canaries) or captures_any(host, safety.canaries):
        codes.append("CANARY_COLLISION")
    if host in safety.allowlist:
        codes.append("ALLOWLIST_EXACT")
    elif listed_cover(host, safety.allowlist):
        codes.append("ALLOWLIST_CHILD")
    if any(d != host for d in captures_any(host, safety.allowlist)):
        codes.append("ALLOWLIST_CAPTURE")
    if listed_cover(host, safety.legitimate):
        codes.append("LEGIT_CORPUS")
    if any(d != host for d in captures_any(host, safety.legitimate)):
        codes.append("LEGIT_CAPTURE")
    if host in safety.shared_platforms:
        codes.append("SHARED_PLATFORM_ROOT")
    elif listed_cover(host, safety.shared_platforms):
        codes.append("SHARED_PLATFORM")
    if registrable is not None and registrable != host:
        codes.append("SCOPE_WIDENS")
    return codes


def classify(source_hosts, live_domains, safety):
    """source_hosts: {source_id: {normalized_host: raw}}. Returns rows for all
    hosts plus the NEW candidate rows."""
    all_hosts = set()
    for hosts in source_hosts.values():
        all_hosts.update(hosts)
    rows = []
    new_hosts = set()
    for host in sorted(all_hosts):
        cover = listed_cover(host, live_domains)
        if cover == host:
            status = "EXACT_PROTECTED"
        elif cover:
            status = "PARENT_PROTECTED"
        else:
            status = "NEW"
            new_hosts.add(host)
        rows.append({
            "host": host,
            "in_hagezi": host in source_hosts.get("hagezi", {}),
            "in_stevenblack": host in source_hosts.get("stevenblack", {}),
            "live_status": status,
            "covering_domain": cover or "",
        })

    candidates = []
    for row in rows:
        if row["live_status"] != "NEW":
            continue
        host = row["host"]
        registrable = safety.psl.registrable_domain(host)
        codes = safety_codes(host, registrable, safety)
        raws = [hosts[host] for hosts in source_hosts.values() if host in hosts]
        if any(r.strip().lower().rstrip(".").startswith("www.") for r in raws):
            codes.append("WWW_STRIPPED")
        source_count = int(row["in_hagezi"]) + int(row["in_stevenblack"])
        if row["in_hagezi"] and not row["in_stevenblack"]:
            codes.append("GPL_SOURCE_ONLY")
        if any(c in BLOCKED_CODES for c in codes):
            status, tier = "BLOCKED", "X"
        elif any(c in REVIEW_CODES for c in codes):
            status, tier = "REVIEW", "R"
        else:
            status = "CLEAR"
            if source_count == 2:
                tier = "A"
            elif row["in_stevenblack"]:
                tier = "B"
            else:
                tier = "C"
        candidates.append({
            "candidate_host": host,
            "registrable_domain": registrable or "",
            "scope_change": "WIDENS" if "SCOPE_WIDENS" in codes else "SAME",
            "live_status": "NEW",
            "in_hagezi": row["in_hagezi"],
            "in_stevenblack": row["in_stevenblack"],
            "source_count": source_count,
            "redundant_with": strict_parent_cover(host, new_hosts) or "",
            "safety_status": status,
            "safety_codes": ";".join(codes),
            "priority_tier": tier,
        })
    candidates.sort(key=lambda c: (TIER_ORDER[c["priority_tier"]], c["candidate_host"]))
    return rows, candidates


# ---------------------------------------------------------------------------
# Reports.
# ---------------------------------------------------------------------------

CANDIDATE_COLUMNS = [
    "candidate_host", "registrable_domain", "scope_change", "live_status",
    "in_hagezi", "in_stevenblack", "source_count", "redundant_with",
    "safety_status", "safety_codes", "priority_tier",
    "hagezi_commit", "stevenblack_commit", "live_ota_version", "run_date_utc",
]


def _yn(value):
    return "yes" if value else "no"


def write_outputs(out_dir, run_meta, rows, candidates):
    os.makedirs(out_dir, exist_ok=True)
    commits = {s["id"]: s["commit"] for s in run_meta["sources"]}
    extra = {
        "hagezi_commit": commits.get("hagezi", ""),
        "stevenblack_commit": commits.get("stevenblack", ""),
        "live_ota_version": run_meta["live_ota"]["package_version"],
        "run_date_utc": run_meta["run_started_utc"][:10],
    }
    with open(os.path.join(out_dir, "discovery_candidates.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CANDIDATE_COLUMNS)
        w.writeheader()
        for c in candidates:
            out = dict(c, **extra)
            out["in_hagezi"] = _yn(c["in_hagezi"])
            out["in_stevenblack"] = _yn(c["in_stevenblack"])
            w.writerow(out)

    with gzip.open(os.path.join(out_dir, "discovery_all.csv.gz"), "wt", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["host", "in_hagezi", "in_stevenblack", "live_status", "covering_domain"])
        for r in rows:
            w.writerow([r["host"], _yn(r["in_hagezi"]), _yn(r["in_stevenblack"]), r["live_status"], r["covering_domain"]])

    def tier_file(name, tier, header):
        hosts = [c["candidate_host"] for c in candidates if c["priority_tier"] == tier and not c["redundant_with"]]
        with open(os.path.join(out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
            for line in header:
                fh.write(f"# {line}\n")
            for h in hosts:
                fh.write(h + "\n")
        return len(hosts)

    common = [
        f"EyeGuard discovery {run_meta['run_started_utc']} - live OTA {extra['live_ota_version']}",
        "NOT approved. Verify every domain yourself before adding it with the Dataset Builder.",
    ]
    tier_file("review_tier_A.txt", "A", common + ["Tier A: in both HaGeZi and StevenBlack, safety CLEAR, scope SAME."])
    tier_file("review_tier_B.txt", "B", common + ["Tier B: StevenBlack only (MIT), safety CLEAR, scope SAME."])
    tier_file("review_tier_C_informational.txt", "C", common + [
        "Tier C: HaGeZi only (GPL-3.0). INFORMATIONAL ONLY until licensing is resolved. Do not import."])
    with open(os.path.join(out_dir, "review_blocked_X.csv"), "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["candidate_host", "safety_codes", "in_hagezi", "in_stevenblack"])
        for c in candidates:
            if c["priority_tier"] == "X":
                w.writerow([c["candidate_host"], c["safety_codes"], _yn(c["in_hagezi"]), _yn(c["in_stevenblack"])])

    with open(os.path.join(out_dir, "source_metadata.json"), "w", encoding="utf-8") as fh:
        json.dump(run_meta, fh, indent=2, sort_keys=True)
        fh.write("\n")

    report = render_report(run_meta, rows, candidates)
    with open(os.path.join(out_dir, "discovery_report.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(report)
    return report


def _counts(items, key):
    out = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return out


def render_report(run_meta, rows, candidates):
    lines = []
    add = lines.append
    live = run_meta["live_ota"]
    add("# EyeGuard Weekly Domain Discovery Report")
    add("")
    add(f"- Status: **{run_meta['status']}**")
    add(f"- Run started (UTC): {run_meta['run_started_utc']}")
    add(f"- Tool version: {run_meta['tool_version']}")
    add(f"- Live OTA: version `{live['package_version']}`, {live['record_count']:,} domains, "
        f"signature verified: {live['signature_verified']}")
    add("- **Nothing was imported, approved, signed or published. Live OTA files were not modified.**")
    add("")
    add("## 1. Sources (pinned and verified)")
    add("")
    add("| Source | Licence | Commit | Bytes | Blob SHA-1 verified | Header count | Parsed | Unique hosts | Invalid | Malformed |")
    add("|---|---|---|---|---|---|---|---|---|---|")
    for s in run_meta["sources"]:
        add(f"| {s['name']} | {s['license']} | `{s['commit'][:12]}` | {s['bytes']:,} | yes | "
            f"{s['declared_count']:,} | {s['parsed_entries']:,} | {s['unique_normalized_hosts']:,} | "
            f"{s['invalid_hostnames']:,} | {s['malformed_lines']:,} |")
    add("")
    add("## 2. Comparison with the live EyeGuard list")
    add("")
    add("| Source | Exact protected | Parent protected | NEW |")
    add("|---|---|---|---|")
    for sid, label in (("hagezi", "HaGeZi NSFW"), ("stevenblack", "StevenBlack porn-only")):
        sub = [r for r in rows if r[f"in_{sid}"]]
        c = _counts(sub, "live_status")
        add(f"| {label} | {c.get('EXACT_PROTECTED', 0):,} | {c.get('PARENT_PROTECTED', 0):,} | {c.get('NEW', 0):,} |")
    both = sum(1 for r in rows if r["in_hagezi"] and r["in_stevenblack"])
    add("")
    add(f"Hosts listed by both sources: {both:,}. All unique hosts: {len(rows):,}.")
    add("")
    add("## 3. Review tiers (NEW hosts only)")
    add("")
    tiers = _counts(candidates, "priority_tier")
    redundant = sum(1 for c in candidates if c["redundant_with"])
    add("| Tier | Meaning | Count |")
    add("|---|---|---|")
    add(f"| A | Both sources, CLEAR, scope SAME | {tiers.get('A', 0):,} |")
    add(f"| B | StevenBlack only (MIT), CLEAR, scope SAME | {tiers.get('B', 0):,} |")
    add(f"| C | HaGeZi only (GPL-3.0), CLEAR, scope SAME. **Informational only.** | {tiers.get('C', 0):,} |")
    add(f"| R | Needs review (see codes) | {tiers.get('R', 0):,} |")
    add(f"| X | Blocked by safety rules | {tiers.get('X', 0):,} |")
    add("")
    add(f"NEW hosts whose parent is also a NEW candidate (`redundant_with`): {redundant:,}. "
        "Tier review files list only the parents.")
    add("")
    add("## 4. Safety findings")
    add("")
    code_counts = {}
    examples = {}
    for c in candidates:
        for code in filter(None, c["safety_codes"].split(";")):
            code_counts[code] = code_counts.get(code, 0) + 1
            examples.setdefault(code, [])
            if len(examples[code]) < 5:
                examples[code].append(c["candidate_host"])
    if code_counts:
        add("| Code | Severity | Count | Examples |")
        add("|---|---|---|---|")
        for code in sorted(code_counts, key=lambda k: (-code_counts[k], k)):
            sev = "BLOCKED" if code in BLOCKED_CODES else "REVIEW" if code in REVIEW_CODES else "INFO"
            add(f"| {code} | {sev} | {code_counts[code]:,} | {', '.join(examples[code])} |")
    else:
        add("No safety codes raised.")
    add("")
    blocked = [c for c in candidates if c["priority_tier"] == "X"]
    add(f"### Blocked candidates (Tier X): {len(blocked):,}")
    add("")
    for c in blocked[:200]:
        add(f"- `{c['candidate_host']}`: {c['safety_codes']}")
    if len(blocked) > 200:
        add(f"- ... {len(blocked) - 200:,} more in `review_blocked_X.csv`")
    add("")
    add("## 5. Live OTA integrity during the run")
    add("")
    guard = run_meta.get("live_guard", {})
    add(f"- Start: manifest `{live['manifest_sha256'][:16]}`, snapshot `{live['snapshot_sha256'][:16]}`, "
        f"domains.bin `{live['sha256_gzip'][:16]}`")
    if guard:
        add(f"- End: manifest `{guard['manifest_sha256'][:16]}`, snapshot `{guard['snapshot_sha256'][:16]}`, "
            f"domains.bin `{guard['sha256_gzip'][:16]}`")
        add(f"- Unchanged during run: **{guard['unchanged']}**")
    add("")
    add("## 6. Owner next steps")
    add("")
    add("1. Review `review_tier_A.txt` and `review_tier_B.txt`. Verify each domain yourself.")
    add("2. Add confirmed domains locally with the Dataset Builder (`bulk-add-verified`); it re-runs its own checks.")
    add("3. Never bulk-import Tier C (GPL-3.0, informational), Tier R or Tier X.")
    add("4. Publishing remains the existing owner-confirmed, locally signed process.")
    add("")
    return "\n".join(lines)


def render_failure_report(started, error):
    return "\n".join([
        "# EyeGuard Weekly Domain Discovery Report",
        "",
        "- Status: **FAILED**",
        f"- Run started (UTC): {started}",
        f"- Failure code: `{error.code}`",
        f"- Detail: {error.message}",
        "",
        "No candidates were produced. Nothing was imported, approved, signed or published.",
        "",
    ])


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def run(cfg, fetcher, safety, public_key_der, out_dir, pins=None, now=None):
    pins = pins or {}
    started = (now or datetime.datetime.now(datetime.timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(out_dir, exist_ok=True)
    try:
        live_domains, live_meta = load_live_ota(fetcher, cfg, public_key_der)
        source_hosts = {}
        source_meta = []
        for src in cfg["sources"]:
            hosts, meta = download_source(fetcher, src, pins.get(src["id"]), cfg["max_malformed_ratio"])
            source_hosts[src["id"]] = hosts
            source_meta.append(meta)
        rows, candidates = classify(source_hosts, live_domains, safety)
        end = live_fingerprint(fetcher, cfg)
        unchanged = all(end[k] == live_meta[k] for k in ("manifest_sha256", "snapshot_sha256", "sha256_gzip"))
        run_meta = {
            "status": "SUCCESS" if unchanged else "SUCCESS_LIVE_CHANGED_DURING_RUN",
            "tool_version": TOOL_VERSION,
            "run_started_utc": started,
            "live_ota": live_meta,
            "live_guard": dict(end, unchanged=unchanged),
            "sources": source_meta,
            "counts": {
                "all_unique_hosts": len(rows),
                "new_hosts": len(candidates),
                "tiers": _counts(candidates, "priority_tier"),
            },
        }
        report = write_outputs(out_dir, run_meta, rows, candidates)
        return EXIT_OK, report
    except DiscoveryError as err:
        report = render_failure_report(started, err)
        with open(os.path.join(out_dir, "discovery_report.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
        with open(os.path.join(out_dir, "source_metadata.json"), "w", encoding="utf-8") as fh:
            json.dump({"status": "FAILED", "run_started_utc": started, "failure_code": err.code,
                       "detail": err.message, "tool_version": TOOL_VERSION}, fh, indent=2)
            fh.write("\n")
        return EXIT_VALIDATION, report


def main(argv=None):
    parser = argparse.ArgumentParser(description="EyeGuard read-only weekly domain discovery")
    parser.add_argument("--out", required=True, help="output directory for reports")
    parser.add_argument("--config", default=os.path.join(HERE, "sources.json"))
    parser.add_argument("--pin", action="append", default=[], metavar="SOURCE_ID=COMMIT_SHA",
                        help="use a specific upstream commit instead of the latest")
    args = parser.parse_args(argv)

    pins = {}
    for item in args.pin:
        if "=" not in item:
            parser.error(f"bad --pin {item!r}")
        key, value = item.split("=", 1)
        pins[key.strip()] = value.strip().lower()

    with open(args.config, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    safety = SafetyData(HERE)
    key_text = _read_text(os.path.join(HERE, cfg["live_ota"]["public_key_file"])).strip()
    public_key_der = base64.b64decode(key_text, validate=True)
    fetcher = Fetcher(cfg["allowed_hosts"], cfg["request_timeout_seconds"], cfg["request_retries"],
                      token=os.environ.get("GH_TOKEN") or None)
    code, report = run(cfg, fetcher, safety, public_key_der, args.out, pins=pins)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report.split("## 4.")[0] if code == EXIT_OK else report)
    print(report.splitlines()[2] if len(report.splitlines()) > 2 else report)
    return code


if __name__ == "__main__":
    sys.exit(main())
