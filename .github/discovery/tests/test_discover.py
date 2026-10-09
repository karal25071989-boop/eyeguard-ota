"""Offline tests for discover.py. No network access; no real keys."""

import base64
import csv
import gzip
import hashlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DISCOVERY = os.path.dirname(HERE)
sys.path.insert(0, DISCOVERY)

import discover as d  # noqa: E402

# Throwaway test key (private scalar used only inside these tests).
_TEST_D = 0x1D2C3B4A5968778695A4B3C2D1E0F00112233445566778899AABBCCDDEEFF011


def _test_public_spki():
    qx, qy = d._scalar_mult(_TEST_D, d._G)
    return d._SPKI_P256_PREFIX + b"\x04" + qx.to_bytes(32, "big") + qy.to_bytes(32, "big")


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def _test_sign(message, k=0x5A5A5A5A12345678ABCDEF0011223344556677889900AABBCCDDEEFF00112233):
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    r = d._scalar_mult(k, d._G)[0] % d._N
    s = pow(k, -1, d._N) * (e + r * _TEST_D) % d._N
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


class FakeFetcher(d.Fetcher):
    def __init__(self, responses, allowed_hosts=("api.github.com", "raw.githubusercontent.com", "ota.example.invalid")):
        super().__init__(allowed_hosts, timeout=1, retries=1)
        self.responses = dict(responses)
        self.requested = []

    def get(self, url, max_bytes, accept=None):
        self.check_url(url)
        self.requested.append(url)
        if url not in self.responses:
            raise d.DiscoveryError("DOWNLOAD_FAILED", url)
        data = self.responses[url]
        if len(data) > max_bytes:
            raise d.DiscoveryError("DOWNLOAD_TOO_LARGE", url)
        return data


def _src(**over):
    base = {
        "id": "hagezi", "name": "Test HaGeZi", "owner": "o", "repo": "r", "branch": "main",
        "path": "list.txt", "format": "domains", "license": "GPL-3.0", "informational_only": True,
        "expected_header_lines": ["# Title: Test list"],
        "count_header_regex": r"^# Number of entries: ([0-9,]+)\s*$",
        "min_entries": 1, "max_entries": 1000, "max_bytes": 100000,
    }
    base.update(over)
    return base


def _domains_list(hosts, title="# Title: Test list", count=None):
    n = len(hosts) if count is None else count
    return ("\n".join([title, f"# Number of entries: {n:,}", "#"] + list(hosts)) + "\n").encode()


def _hosts_list(hosts, count=None):
    n = len(hosts) if count is None else count
    lines = ["# Title: StevenBlack/hosts extension porn", f"# Number of unique domains: {n:,}",
             "127.0.0.1 localhost", "::1 localhost", "0.0.0.0 0.0.0.0", "255.255.255.255 broadcasthost"]
    lines += [f"0.0.0.0 {h}" for h in hosts]
    return ("\n".join(lines) + "\n").encode()


class NormalizeTest(unittest.TestCase):
    def test_matches_android_rules(self):
        cases = {
            "WWW.Example.COM.": "example.com",
            "www.www.example.com": "example.com",
            "https://www.example.com/path?q=1#x": "example.com",
            "user@sub.example.com:8443": "sub.example.com",
            "bücher.de": "xn--bcher-kva.de",
            "1.2.3.4": None,
            "localhost": None,
            "a.localhost": None,
            "com": None,
            "under_score.com": None,
            "-bad.com": None,
            "bad-.com": None,
            "has space.com": None,
            "javascript:alert(1)": None,
            ("a" * 64) + ".com": None,
            "": None,
        }
        for raw, expected in cases.items():
            self.assertEqual(d.normalize_host(raw), expected, raw)


class MatchingTest(unittest.TestCase):
    def test_parent_label_walk_matches_siteshield_domain_match(self):
        listed = {"example.com", "com.au", "xhaccess.com"}
        self.assertEqual(d.listed_cover("example.com", listed), "example.com")
        self.assertEqual(d.listed_cover("a.b.example.com", listed), "example.com")
        self.assertEqual(d.listed_cover("www.xhaccess.com", listed), "xhaccess.com")
        self.assertIsNone(d.listed_cover("notexample.com", listed))
        self.assertIsNone(d.listed_cover("example.org", listed))
        self.assertEqual(d.listed_cover("shop.com.au", listed), "com.au")

    def test_never_matches_single_label_tld(self):
        self.assertIsNone(d.listed_cover("anything.com", {"com"}))
        self.assertEqual(d.listed_cover("com", {"com"}), "com")

    def test_strict_parent_and_capture(self):
        self.assertEqual(d.strict_parent_cover("a.new.com", {"new.com", "a.new.com"}), "new.com")
        self.assertIsNone(d.strict_parent_cover("new.com", {"new.com"}))
        self.assertEqual(d.captures_any("google.com", {"maps.google.com", "google.co.in"}), ["maps.google.com"])


class PublicSuffixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psl = d.SafetyData(DISCOVERY).psl

    def test_registrable_domain(self):
        self.assertEqual(self.psl.registrable_domain("sbi.co.in"), "sbi.co.in")
        self.assertEqual(self.psl.registrable_domain("i.4cdn.org"), "4cdn.org")
        self.assertEqual(self.psl.registrable_domain("x.y.example.com"), "example.com")
        self.assertEqual(self.psl.registrable_domain("someone.blogspot.com"), "someone.blogspot.com")
        self.assertIsNone(self.psl.registrable_domain("co.in"))

    def test_public_suffix(self):
        self.assertTrue(self.psl.is_public_suffix("co.in"))
        self.assertTrue(self.psl.is_public_suffix("gov.in"))
        self.assertFalse(self.psl.is_public_suffix("example.com"))


class EcdsaTest(unittest.TestCase):
    def test_valid_signature_verifies(self):
        msg = b"eyeguard domains"
        self.assertTrue(d.ecdsa_p256_verify(_test_public_spki(), msg, _test_sign(msg)))

    def test_tampering_is_rejected(self):
        msg = b"eyeguard domains"
        sig = _test_sign(msg)
        self.assertFalse(d.ecdsa_p256_verify(_test_public_spki(), msg + b"!", sig))
        bad = bytearray(sig)
        bad[-1] ^= 0x01
        self.assertFalse(d.ecdsa_p256_verify(_test_public_spki(), msg, bytes(bad)))
        self.assertFalse(d.ecdsa_p256_verify(b"not a key", msg, sig))
        self.assertFalse(d.ecdsa_p256_verify(_test_public_spki(), msg, b"\x30\x00"))

    def test_production_public_key_parses(self):
        with open(os.path.join(DISCOVERY, "ota_public_key_spki.txt"), encoding="utf-8") as fh:
            der = base64.b64decode(fh.read().strip(), validate=True)
        d.parse_spki_p256(der)


class SourceParsingTest(unittest.TestCase):
    def test_valid_domains_list(self):
        hosts, stats = d.parse_source(_src(), _domains_list(["a.com", "www.b.com", "bad_host.com"]), 0.5)
        self.assertEqual(set(hosts), {"a.com", "b.com"})
        self.assertEqual(stats["invalid_hostnames"], 1)
        self.assertEqual(hosts["b.com"], "www.b.com")

    def test_hosts_format_skips_boilerplate(self):
        src = _src(id="stevenblack", format="hosts", expected_header_lines=["# Title: StevenBlack/hosts extension porn"],
                   count_header_regex=r"^# Number of unique domains: ([0-9,]+)\s*$")
        hosts, stats = d.parse_source(src, _hosts_list(["x.com", "y.net"]), 0.0)
        self.assertEqual(set(hosts), {"x.com", "y.net"})
        self.assertEqual(stats["boilerplate_lines"], 4)

    def test_rejections(self):
        cases = [
            ("SOURCE_COUNT_MISMATCH", _src(), _domains_list(["a.com"], count=2)),
            ("SOURCE_HEADER_MISSING", _src(), _domains_list(["a.com"], title="# Title: Something else")),
            ("SOURCE_BINARY", _src(), b"# Title: Test list\n\x00"),
            ("SOURCE_NOT_UTF8", _src(), b"# Title: Test list\n\xff\xfe\n"),
            ("SOURCE_COUNT_HEADER_MISSING", _src(), b"# Title: Test list\na.com\n"),
            ("SOURCE_COUNT_OUT_OF_BOUNDS", _src(min_entries=5), _domains_list(["a.com"])),
        ]
        for code, src, data in cases:
            with self.assertRaises(d.DiscoveryError) as ctx:
                d.parse_source(src, data, 0.5)
            self.assertEqual(ctx.exception.code, code)

    def test_malformed_ratio(self):
        data = _domains_list(["a.com", "two words", "b.com"], count=2)
        with self.assertRaises(d.DiscoveryError) as ctx:
            d.parse_source(_src(), data, 0.1)
        self.assertEqual(ctx.exception.code, "SOURCE_TOO_MANY_MALFORMED")
        hosts, stats = d.parse_source(_src(), data, 0.5)
        self.assertEqual(stats["malformed_lines"], 1)


SHA_A = "a" * 40


def _source_responses(src, data, blob=None, size=None):
    path = src["path"]
    return {
        f"https://api.github.com/repos/{src['owner']}/{src['repo']}/commits?path={path}&sha={src['branch']}&per_page=1":
            json.dumps([{"sha": SHA_A, "commit": {"committer": {"date": "2026-10-08T00:00:00Z"}}}]).encode(),
        f"https://api.github.com/repos/{src['owner']}/{src['repo']}/contents/{path}?ref={SHA_A}":
            json.dumps({"sha": blob or d.git_blob_sha1(data), "size": len(data) if size is None else size}).encode(),
        f"https://raw.githubusercontent.com/{src['owner']}/{src['repo']}/{SHA_A}/{path}": data,
    }


class DownloadIntegrityTest(unittest.TestCase):
    def test_verified_download(self):
        src = _src()
        data = _domains_list(["a.com"])
        hosts, meta = d.download_source(FakeFetcher(_source_responses(src, data)), src, None, 0.0)
        self.assertEqual(set(hosts), {"a.com"})
        self.assertEqual(meta["commit"], SHA_A)
        self.assertEqual(meta["git_blob_sha1"], d.git_blob_sha1(data))

    def test_blob_mismatch_rejected(self):
        src = _src()
        data = _domains_list(["a.com"])
        fetcher = FakeFetcher(_source_responses(src, data, blob="b" * 40))
        with self.assertRaises(d.DiscoveryError) as ctx:
            d.download_source(fetcher, src, None, 0.0)
        self.assertEqual(ctx.exception.code, "SOURCE_BLOB_MISMATCH")

    def test_size_mismatch_and_oversize_rejected(self):
        src = _src()
        data = _domains_list(["a.com"])
        with self.assertRaises(d.DiscoveryError) as ctx:
            d.download_source(FakeFetcher(_source_responses(src, data, size=len(data) + 1)), src, None, 0.0)
        self.assertEqual(ctx.exception.code, "SOURCE_SIZE_MISMATCH")
        with self.assertRaises(d.DiscoveryError) as ctx:
            d.download_source(FakeFetcher(_source_responses(src, data, size=10 ** 9)), src, None, 0.0)
        self.assertEqual(ctx.exception.code, "SOURCE_TOO_LARGE")

    def test_pin_must_be_full_sha(self):
        with self.assertRaises(d.DiscoveryError) as ctx:
            d.download_source(FakeFetcher({}), _src(), "main", 0.0)
        self.assertEqual(ctx.exception.code, "PIN_INVALID")

    def test_url_policy(self):
        f = d.Fetcher(["raw.githubusercontent.com"], 1, 1)
        for url, code in (("http://raw.githubusercontent.com/x", "URL_NOT_HTTPS"),
                          ("https://evil.example/x", "URL_HOST_NOT_ALLOWED"),
                          ("https://raw.githubusercontent.com:8443/x", "URL_HOST_NOT_ALLOWED")):
            with self.assertRaises(d.DiscoveryError) as ctx:
                f.check_url(url)
            self.assertEqual(ctx.exception.code, code)


OTA = "https://ota.example.invalid/"


def _ota_cfg():
    return {"live_ota": {
        "manifest_url": OTA + "manifest.json", "manifest_max_bytes": 16384, "snapshot_max_bytes": 65536,
        "domains_max_bytes": 1 << 20, "uncompressed_max_bytes": 1 << 22,
        "signature_algorithm": "SHA256withECDSA", "public_key_file": "unused"}}


def _ota_responses(domains, tamper=None):
    plain = ("\n".join(sorted(domains)) + "\n").encode()
    gz = gzip.compress(plain, mtime=0)
    sig = _test_sign(gz)
    snapshot = {"recordCount": len(domains), "sha256Gzip": hashlib.sha256(gz).hexdigest(),
                "sha256Uncompressed": hashlib.sha256(plain).hexdigest(), "eyeguardPackageVersion": "2026.09.009"}
    manifest = {"preparedAtEpochMs": 1, "version": 1, "domainsUrl": OTA + "domains.bin",
                "snapshotUrl": OTA + "snapshot.json", "signatureAlgorithm": "SHA256withECDSA",
                "signatureBase64": base64.b64encode(sig).decode(), "sha256Gzip": hashlib.sha256(gz).hexdigest()}
    if tamper == "signature":
        manifest["signatureBase64"] = base64.b64encode(_test_sign(gz + b"x")).decode()
    if tamper == "domains":
        gz = gzip.compress(plain + b"extra.com\n", mtime=0)
    if tamper == "count":
        snapshot["recordCount"] = len(domains) + 1
    return {OTA + "manifest.json": json.dumps(manifest).encode(),
            OTA + "snapshot.json": json.dumps(snapshot).encode(),
            OTA + "domains.bin": gz}


class LiveOtaTest(unittest.TestCase):
    def test_valid_live_list(self):
        domains, meta = d.load_live_ota(FakeFetcher(_ota_responses({"example.com", "xhaccess.com"})),
                                        _ota_cfg(), _test_public_spki())
        self.assertEqual(domains, {"example.com", "xhaccess.com"})
        self.assertTrue(meta["signature_verified"])

    def test_tampering_rejected(self):
        for tamper, code in (("signature", "LIVE_SIGNATURE_INVALID"), ("domains", "LIVE_HASH_MISMATCH"),
                             ("count", "LIVE_COUNT_MISMATCH")):
            with self.assertRaises(d.DiscoveryError) as ctx:
                d.load_live_ota(FakeFetcher(_ota_responses({"example.com"}, tamper)), _ota_cfg(), _test_public_spki())
            self.assertEqual(ctx.exception.code, code, tamper)


class ClassificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.safety = d.SafetyData(DISCOVERY)

    def _classify(self):
        hagezi = {h: h for h in ["a.example.com", "new.com", "sub.new.com", "hz-only.org", "x.google.com",
                                 "google.com", "co.in", "foo.gov.in", "i.4cdn.org", "tumblr.com",
                                 "someone.blogspot.com", "example.com"]}
        hagezi["wwwsite.com"] = "www.wwwsite.com"
        steven = {h: h for h in ["new.com", "sb-only.net"]}
        rows, cands = d.classify({"hagezi": hagezi, "stevenblack": steven}, {"example.com"}, self.safety)
        return {r["host"]: r for r in rows}, {c["candidate_host"]: c for c in cands}

    def test_live_status(self):
        rows, cands = self._classify()
        self.assertEqual(rows["example.com"]["live_status"], "EXACT_PROTECTED")
        self.assertEqual(rows["a.example.com"]["live_status"], "PARENT_PROTECTED")
        self.assertEqual(rows["a.example.com"]["covering_domain"], "example.com")
        self.assertNotIn("a.example.com", cands)

    def test_tiers(self):
        _, c = self._classify()
        self.assertEqual(c["new.com"]["priority_tier"], "A")
        self.assertEqual(c["sb-only.net"]["priority_tier"], "B")
        self.assertEqual(c["hz-only.org"]["priority_tier"], "C")
        self.assertIn("GPL_SOURCE_ONLY", c["hz-only.org"]["safety_codes"])
        self.assertEqual(c["wwwsite.com"]["priority_tier"], "C")
        self.assertIn("WWW_STRIPPED", c["wwwsite.com"]["safety_codes"])

    def test_scope_widening_and_redundancy(self):
        _, c = self._classify()
        self.assertEqual(c["sub.new.com"]["scope_change"], "WIDENS")
        self.assertEqual(c["sub.new.com"]["priority_tier"], "R")
        self.assertEqual(c["sub.new.com"]["redundant_with"], "new.com")
        self.assertEqual(c["i.4cdn.org"]["registrable_domain"], "4cdn.org")
        self.assertIn("SCOPE_WIDENS", c["i.4cdn.org"]["safety_codes"])
        self.assertEqual(c["someone.blogspot.com"]["scope_change"], "SAME")
        self.assertEqual(c["someone.blogspot.com"]["priority_tier"], "R")

    def test_false_positive_safeguards(self):
        _, c = self._classify()
        self.assertEqual(c["google.com"]["priority_tier"], "X")
        self.assertIn("ALLOWLIST_EXACT", c["google.com"]["safety_codes"])
        self.assertIn("CANARY_COLLISION", c["google.com"]["safety_codes"])
        self.assertEqual(c["x.google.com"]["priority_tier"], "X")
        self.assertEqual(c["co.in"]["priority_tier"], "X")
        self.assertIn("PUBLIC_SUFFIX", c["co.in"]["safety_codes"])
        self.assertEqual(c["foo.gov.in"]["priority_tier"], "X")
        self.assertIn("OFFICIAL_SUFFIX", c["foo.gov.in"]["safety_codes"])
        self.assertEqual(c["tumblr.com"]["priority_tier"], "X")

    def test_every_allowlisted_and_canary_domain_is_never_clear(self):
        for host in sorted(self.safety.allowlist | self.safety.canaries | self.safety.legitimate):
            _, cands = d.classify({"hagezi": {host: host}, "stevenblack": {host: host}}, set(), self.safety)
            self.assertEqual(cands[0]["safety_status"], "BLOCKED" if cands[0]["priority_tier"] == "X" else "REVIEW",
                             host)
            self.assertNotIn(cands[0]["priority_tier"], ("A", "B", "C"), host)


class EndToEndTest(unittest.TestCase):
    def _cfg(self, hz, sb):
        cfg = _ota_cfg()
        cfg.update({"max_malformed_ratio": 0.005, "sources": [hz, sb]})
        return cfg

    def test_run_writes_reports_only(self):
        hz = _src(path="hz.txt")
        sb = _src(id="stevenblack", name="Test SB", owner="s", repo="h", branch="master", path="hosts",
                  format="hosts", license="MIT", informational_only=False,
                  expected_header_lines=["# Title: StevenBlack/hosts extension porn"],
                  count_header_regex=r"^# Number of unique domains: ([0-9,]+)\s*$")
        responses = {}
        responses.update(_ota_responses({"example.com"}))
        responses.update(_source_responses(hz, _domains_list(["new.com", "hz-only.org", "google.com"])))
        responses.update(_source_responses(sb, _hosts_list(["new.com", "example.com"])))
        with tempfile.TemporaryDirectory() as tmp:
            code, report = d.run(self._cfg(hz, sb), FakeFetcher(responses), d.SafetyData(DISCOVERY),
                                 _test_public_spki(), tmp)
            self.assertEqual(code, d.EXIT_OK)
            self.assertEqual(sorted(os.listdir(tmp)), sorted([
                "discovery_candidates.csv", "discovery_all.csv.gz", "discovery_report.md", "source_metadata.json",
                "review_tier_A.txt", "review_tier_B.txt", "review_tier_C_informational.txt", "review_blocked_X.csv"]))
            with open(os.path.join(tmp, "discovery_candidates.csv"), encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual([r["candidate_host"] for r in rows], ["new.com", "hz-only.org", "google.com"])
            self.assertEqual([r["priority_tier"] for r in rows], ["A", "C", "X"])
            with open(os.path.join(tmp, "review_tier_A.txt"), encoding="utf-8") as fh:
                self.assertIn("new.com\n", fh.read())
            with open(os.path.join(tmp, "review_tier_C_informational.txt"), encoding="utf-8") as fh:
                self.assertIn("INFORMATIONAL ONLY", fh.read())
            self.assertIn("Nothing was imported, approved, signed or published", report)
            with open(os.path.join(tmp, "source_metadata.json"), encoding="utf-8") as fh:
                meta = json.load(fh)
            self.assertTrue(meta["live_guard"]["unchanged"])

    def test_failure_produces_failed_report_and_no_candidates(self):
        hz = _src(path="hz.txt")
        responses = {}
        responses.update(_ota_responses({"example.com"}))
        responses.update(_source_responses(hz, _domains_list(["a.com"]), blob="c" * 40))
        with tempfile.TemporaryDirectory() as tmp:
            code, report = d.run(self._cfg(hz, hz), FakeFetcher(responses), d.SafetyData(DISCOVERY),
                                 _test_public_spki(), tmp)
            self.assertEqual(code, d.EXIT_VALIDATION)
            self.assertIn("SOURCE_BLOB_MISMATCH", report)
            self.assertNotIn("discovery_candidates.csv", os.listdir(tmp))


class RepositoryHygieneTest(unittest.TestCase):
    def test_no_private_key_material(self):
        for root, _, files in os.walk(DISCOVERY):
            for name in files:
                low = name.lower()
                self.assertFalse(low.endswith((".pem", ".key", ".p12", ".pfx", ".p8")), name)
                if name.endswith(".py"):
                    continue
                with open(os.path.join(root, name), "rb") as fh:
                    blob = fh.read()
                self.assertNotIn(b"PRIVATE KEY", blob, name)

    def test_only_reads_allowlisted_hosts(self):
        with open(os.path.join(DISCOVERY, "sources.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
        self.assertEqual(set(cfg["allowed_hosts"]),
                         {"api.github.com", "raw.githubusercontent.com", "karal25071989-boop.github.io"})


if __name__ == "__main__":
    unittest.main()
