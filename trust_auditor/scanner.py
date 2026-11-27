from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Iterable

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

TEXT_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".yml", ".yaml",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".rs", ".go", ".java", ".kt",
    ".sol", ".toml", ".ini", ".cfg", ".conf", ".env", ".txt", ".md", ".html", ".htm",
    ".css", ".xml", ".gradle", ".rb", ".php", ".pl", ".lua", ".swift", ".dart",
}
SKIP_DIRS = {"node_modules", "vendor", "dist", "build", "coverage", ".next", ".cache", ".git", "target", ".venv", "venv", "__pycache__"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    category: str
    repository: str
    path: str
    line: int
    summary: str
    evidence: str
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    summary: str
    confidence: str = "medium"
    redact_all: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    # Context is required around 32-byte hex so ordinary SHA-256 checksums do not become Critical findings.
    Rule("HARDCODED_EVM_KEY", "CRITICAL", "secret-exposure", _rx(r"(?:private[_ -]?key|secret[_ -]?key|wallet[_ -]?key)[^\n]{0,100}(?:0x)?[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"), "Possible 32-byte wallet private key committed to source", "high", True),
    Rule("GITHUB_TOKEN_LITERAL", "CRITICAL", "secret-exposure", _rx(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "Possible GitHub access token committed to source", "high", True),
    Rule("AWS_ACCESS_KEY", "CRITICAL", "secret-exposure", _rx(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "Possible AWS access-key identifier committed to source", "high", True),
    Rule("SLACK_TOKEN", "CRITICAL", "secret-exposure", _rx(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Possible Slack token committed to source", "high", True),
    Rule("MNEMONIC_ASSIGNMENT", "HIGH", "credential-collection", _rx(r"(?:seed|mnemonic|recovery\s*phrase)[^\n=]{0,40}[=:]\s*['\"](?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}['\"]"), "Mnemonic/seed-like phrase appears assigned in source", "high", True),
    Rule("PRIVATE_KEY_PROMPT", "HIGH", "credential-collection", _rx(r"(?:\binput\s*\(|\bprompt\s*\(|readline\s*\(|scanf\s*\(|\bread\s*\()[^\n]{0,100}(?:private[_ -]?key|secret[_ -]?key|mnemonic|seed[_ -]?phrase)"), "Code appears to request a wallet secret from a user", "high"),
    Rule("PASSWORD_PROMPT", "HIGH", "credential-collection", _rx(r"(?:\binput\s*\(|\bprompt\s*\(|readline\s*\(|scanf\s*\(|\bread\s*\()[^\n]{0,100}(?:password|passphrase|api[_ -]?key|auth[_ -]?token|session[_ -]?cookie)"), "Code appears to request sensitive authentication material", "medium"),
    Rule("CLIPBOARD_READ", "MEDIUM", "clipboard", _rx(r"(?:clipboard\.read|readText\(|pyperclip\.paste|Get-Clipboard|navigator\.clipboard\.readText)"), "Reads clipboard contents", "medium"),
    Rule("CLIPBOARD_WRITE", "MEDIUM", "clipboard", _rx(r"(?:clipboard\.write|writeText\(|pyperclip\.copy|Set-Clipboard|navigator\.clipboard\.writeText)"), "Writes clipboard contents", "medium"),
    Rule("WALLET_ADDRESS_REPLACE", "HIGH", "clipboard", _rx(r"(?:navigator\.clipboard|clipboard\.(?:readText|writeText)|readText\(|writeText\()[^\n]{0,240}(?:0x[a-f0-9]{40}|(?:btc|eth|sol|wallet)[_ -]?address)[^\n]{0,180}(?:replace|write|copy)"), "Possible clipboard wallet-address replacement logic", "medium"),
    Rule("WEBHOOK", "MEDIUM", "network", _rx(r"(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|api\.telegram\.org/bot)"), "Webhook or bot endpoint present", "high"),
    Rule("OUTBOUND_POST", "LOW", "network", _rx(r"(?:requests\.post|axios\.post|fetch\s*\(|http\.post|https\.request|urllib\.request|curl\s+[^\n]*(?:-d|--data)|Invoke-WebRequest|Invoke-RestMethod)"), "Outbound HTTP/network operation present", "medium"),
    Rule("RAW_SOCKET", "MEDIUM", "network", _rx(r"(?:socket\.socket|net\.Socket|TcpClient|WebSocket\s*\()"), "Raw socket or websocket communication present", "medium"),
    Rule("BASE64_EXEC", "HIGH", "obfuscation", _rx(r"(?:eval|exec|Function)\s*\([^\n]{0,120}(?:b64decode|atob|fromCharCode|base64)"), "Decoded/obfuscated content appears to be executed", "high"),
    Rule("EVAL_EXEC", "MEDIUM", "obfuscation", _rx(r"\b(?:eval|exec)\s*\("), "Dynamic code execution present", "medium"),
    Rule("SHELL_DOWNLOAD_EXEC", "HIGH", "install-execution", _rx(r"(?:curl|wget)[^\n|;]{0,220}(?:\||;|&&)\s*(?:bash|sh|zsh|python|node)|(?:iwr|Invoke-WebRequest)[^\n]{0,220}(?:iex|Invoke-Expression)"), "Downloads content and executes it in one chain", "high"),
    Rule("POWERSHELL_ENCODED", "HIGH", "obfuscation", _rx(r"powershell(?:\.exe)?[^\n]{0,120}-(?:enc|encodedcommand)\b"), "PowerShell encoded command execution", "high"),
    Rule("UNLIMITED_APPROVAL", "HIGH", "wallet-permission", _rx(r"(?:approve|allowance|permit)[^\n]{0,180}(?:MaxUint256|MAX_UINT|2\s*\*\*\s*256\s*-\s*1|0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)"), "Possible unlimited token approval/permit", "medium"),
    Rule("SIGN_TX", "MEDIUM", "wallet-transaction", _rx(r"(?:signTransaction|sendTransaction|sendRawTransaction|eth_sendTransaction|wallet\.sendTransaction|signAndSendTransaction)"), "Code can sign or submit blockchain transactions", "medium"),
    Rule("ENV_SECRET_READ", "LOW", "credential-access", _rx(r"(?:process\.env|os\.environ|os\.getenv|getenv\(|env::var)[^\n]{0,100}(?:PRIVATE_KEY|SEED|MNEMONIC|PASSWORD|TOKEN|SECRET|COOKIE|API_KEY)"), "Reads a sensitive environment variable", "medium"),
    Rule("BROWSER_STORAGE_TOKEN", "MEDIUM", "credential-access", _rx(r"(?:localStorage|sessionStorage|document\.cookie)[^\n]{0,120}(?:token|auth|session|key|wallet)"), "Reads or writes sensitive browser storage", "medium"),
    Rule("WORKFLOW_WRITE_ALL", "HIGH", "ci-security", _rx(r"(?m)^\s*permissions\s*:\s*write-all\s*$"), "GitHub Actions workflow grants broad write-all permissions", "high"),
    Rule("WORKFLOW_SECRET_SHELL", "HIGH", "ci-security", _rx(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}[^\n]{0,220}(?:curl|wget|Invoke-WebRequest|nc\s|ssh\s)"), "GitHub Actions secret may be passed to a network-capable command", "medium", True),
)

# Only actual sensitive retrieval expressions count as sources; UI copy and generic
# references to clipboard/password are not proof of collection.
SENSITIVE_SOURCE = _rx(r"(?:\binput\s*\([^)]*(?:private[_ -]?key|secret[_ -]?key|seed[_ -]?phrase|mnemonic|password|passphrase|api[_ -]?key|auth[_ -]?token)|\bprompt\s*\([^)]*(?:private[_ -]?key|secret[_ -]?key|seed[_ -]?phrase|mnemonic|password|passphrase|api[_ -]?key|auth[_ -]?token)|(?:process\.env|os\.getenv|getenv)\s*\(?[^)\n]*(?:PRIVATE_KEY|SEED|MNEMONIC|PASSWORD|TOKEN|SECRET|API_KEY)|localStorage\.getItem\s*\([^)]*(?:token|auth|secret|key)|document\.cookie|(?:navigator\.)?clipboard\.readText\s*\()")
NETWORK_SINK = _rx(r"(?:requests\.post|axios\.post|fetch\s*\(|http\.post|https\.request|webhook|api\.telegram\.org|discord(?:app)?\.com/api/webhooks|socket\.send|sendall\(|curl\s|Invoke-RestMethod|Invoke-WebRequest)")
SUSPICIOUS_INSTALL = _rx(r"(?:curl|wget|powershell|Invoke-WebRequest|bash\s+-c|sh\s+-c|node\s+-e|python\s+-c)")

def _is_detector_definition(text: str, match: re.Match[str]) -> bool:
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.start())
    line = text[line_start:] if line_end < 0 else text[line_start:line_end]
    stripped = line.lstrip()
    if stripped.startswith(("#", "//", "/*", "*", "<!--", ";")):
        return True
    if "_rx(" in line or "re.compile(" in line:
        return True
    return bool(re.match(r"(?:SENSITIVE_SOURCE|NETWORK_SINK|SUSPICIOUS_INSTALL)\s*=", stripped))



def is_text_candidate(path: str, size: int, max_size: int = 1_000_000) -> bool:
    if size <= 0 or size > max_size:
        return False
    p = PurePosixPath(path)
    if any(part in SKIP_DIRS for part in p.parts):
        return False
    if p.name in {"Dockerfile", "Makefile", "Procfile", "requirements.txt", "requirements-dev.txt", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "Gemfile", "Gemfile.lock"}:
        return True
    return p.suffix.lower() in TEXT_EXTENSIONS


def _redact(line: str, redact_all: bool = False) -> str:
    if redact_all:
        return "[REDACTED POTENTIAL SECRET]"
    line = line.strip().replace("\t", " ")
    line = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b", "[REDACTED_TOKEN]", line)
    line = re.sub(r"(?<![A-Fa-f0-9])(?:0x)?[A-Fa-f0-9]{64}(?![A-Fa-f0-9])", "[REDACTED_64_HEX]", line)
    line = re.sub(r"((?:seed|mnemonic|private[_ -]?key|password|token|secret)[^=:]{0,30}[=:]\s*)[^,}\s]+", r"\1[REDACTED]", line, flags=re.I)
    return line[:260]


def _line_number(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def _finding(rule: Rule, repository: str, path: str, text: str, match: re.Match[str]) -> Finding:
    line = _line_number(text, match.start())
    lines = text.splitlines()
    evidence = lines[line - 1] if 0 < line <= len(lines) else ""
    return Finding(rule.rule_id, rule.severity, rule.category, repository, path, line, rule.summary, _redact(evidence, rule.redact_all), rule.confidence)


def scan_text(repository: str, path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    is_test_fixture = any(part.lower() in {"test", "tests", "fixtures", "testdata"} for part in PurePosixPath(path).parts) or PurePosixPath(path).name.lower().startswith(("test_", "test."))
    is_documentation = PurePosixPath(path).suffix.lower() in {".md", ".rst", ".txt"}
    literal_secret_rules = {"HARDCODED_EVM_KEY", "GITHUB_TOKEN_LITERAL", "AWS_ACCESS_KEY", "SLACK_TOKEN", "MNEMONIC_ASSIGNMENT"}
    for rule in RULES:
        # Tests and prose contain illustrative attack examples and warning copy.
        # Keep literal-secret checks, but do not score examples as live behavior.
        if (is_test_fixture or is_documentation) and rule.rule_id not in literal_secret_rules:
            continue
        hits = 0
        for match in rule.pattern.finditer(text):
            if _is_detector_definition(text, match):
                continue
            line = _line_number(text, match.start())
            if (rule.rule_id, line) in seen:
                continue
            seen.add((rule.rule_id, line))
            findings.append(_finding(rule, repository, path, text, match))
            hits += 1
            if hits >= 8:
                break

    # A proximity-only match is not data flow. Require the retrieved value's
    # variable name to appear inside an outbound network call.
    if not is_test_fixture and not is_documentation:
        assignments = re.compile(r"(?im)^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,400})")
        sources = []
        for assignment in assignments.finditer(text):
            if SENSITIVE_SOURCE.search(assignment.group(2)) and not _is_detector_definition(text, assignment):
                sources.append((assignment.group(1), assignment.start()))
        sinks = [m for m in NETWORK_SINK.finditer(text) if not _is_detector_definition(text, m)]
        for variable, source_position in sources:
            for sink in sinks:
                call_window = text[sink.start():sink.start() + 1200]
                if re.search(rf"\b{re.escape(variable)}\b", call_window):
                    source_line = _line_number(text, source_position)
                    if ("SECRET_TO_NETWORK", source_line) not in seen:
                        findings.append(Finding("SECRET_TO_NETWORK", "CRITICAL", "possible-exfiltration", repository, path, source_line, "A retrieved sensitive value is referenced by an outbound network call", "[REDACTED SENSITIVE FLOW CONTEXT]", "high"))
                        seen.add(("SECRET_TO_NETWORK", source_line))
                    break

    name = PurePosixPath(path).name.lower()
    if name == "package.json":
        try:
            package = json.loads(text)
            scripts = package.get("scripts") or {}
            for hook in ("preinstall", "postinstall", "prepare"):
                command = str(scripts.get(hook, ""))
                if command and SUSPICIOUS_INSTALL.search(command):
                    findings.append(Finding("DANGEROUS_INSTALL_HOOK", "CRITICAL" if hook in {"preinstall", "postinstall"} else "HIGH", "install-execution", repository, path, 1, f"{hook} script downloads or executes external/dynamic content", _redact(command), "high"))
            deps: dict[str, object] = {}
            deps.update(package.get("dependencies") or {})
            deps.update(package.get("devDependencies") or {})
            for dep_name, spec in list(deps.items())[:500]:
                if isinstance(spec, str) and re.match(r"^(?:git\+|https?://|github:)", spec):
                    findings.append(Finding("REMOTE_CODE_DEPENDENCY", "MEDIUM", "dependency", repository, path, 1, f"Dependency {dep_name!r} installs directly from a remote URL/VCS source", f"{dep_name}: [REMOTE SPEC]", "high"))
        except json.JSONDecodeError:
            findings.append(Finding("INVALID_PACKAGE_JSON", "LOW", "hygiene", repository, path, 1, "package.json is not valid JSON", "", "high"))

    if name in {"requirements.txt", "requirements-dev.txt"}:
        for index, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if " @ http" in line or line.startswith(("git+", "http://", "https://")):
                findings.append(Finding("REMOTE_PYTHON_DEPENDENCY", "MEDIUM", "dependency", repository, path, index, "Python dependency is installed directly from a remote URL/VCS source", _redact(line), "high"))
            elif re.fullmatch(r"[A-Za-z0-9_.-]+", line):
                findings.append(Finding("UNPINNED_PYTHON_DEPENDENCY", "LOW", "dependency", repository, path, index, "Python dependency is completely unpinned", _redact(line), "high"))

    return deduplicate(findings)


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, int, str], Finding] = {}
    for finding in findings:
        unique[(finding.repository, finding.path, finding.line, finding.rule_id)] = finding
    return sorted(unique.values(), key=lambda f: (-SEVERITY_RANK[f.severity], f.repository, f.path, f.line, f.rule_id))
