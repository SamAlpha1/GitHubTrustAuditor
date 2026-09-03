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

SKIP_DIRS = {
    "node_modules", "vendor", "dist", "build", "coverage", ".next", ".cache", ".git",
    "target", ".venv", "venv", "__pycache__",
}


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
    Rule("HARDCODED_EVM_KEY", "CRITICAL", "secret-exposure", _rx(r"(?<![A-Fa-f0-9])(?:0x)?[A-Fa-f0-9]{64}(?![A-Fa-f0-9])"), "Possible 32-byte private key or secret literal", "medium", True),
    Rule("GITHUB_TOKEN_LITERAL", "CRITICAL", "secret-exposure", _rx(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "Possible GitHub access token committed to source", "high", True),
    Rule("AWS_ACCESS_KEY", "CRITICAL", "secret-exposure", _rx(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "Possible AWS access-key identifier committed to source", "high", True),
    Rule("SLACK_TOKEN", "CRITICAL", "secret-exposure", _rx(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Possible Slack token committed to source", "high", True),
    Rule("MNEMONIC_ASSIGNMENT", "HIGH", "credential-collection", _rx(r"(?:seed|mnemonic|recovery\s*phrase)[^\n=]{0,40}[=:]\s*['\"](?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}['\"]"), "Mnemonic/seed-like phrase appears assigned in source", "high", True),
    Rule("PRIVATE_KEY_PROMPT", "HIGH", "credential-collection", _rx(r"(?:input|prompt|readline|question|scanf|read)[^\n]{0,100}(?:private[_ -]?key|secret[_ -]?key|mnemonic|seed[_ -]?phrase)"), "Code appears to request a wallet secret from a user", "high"),
    Rule("PASSWORD_PROMPT", "HIGH", "credential-collection", _rx(r"(?:input|prompt|readline|question|scanf|read)[^\n]{0,100}(?:password|passphrase|api[_ -]?key|auth[_ -]?token|session[_ -]?cookie)"), "Code appears to request sensitive authentication material", "medium"),
    Rule("CLIPBOARD_READ", "MEDIUM", "clipboard", _rx(r"(?:clipboard\.read|readText\(|pyperclip\.paste|Get-Clipboard|navigator\.clipboard\.readText)"), "Reads clipboard contents", "medium"),
    Rule("CLIPBOARD_WRITE", "MEDIUM", "clipboard", _rx(r"(?:clipboard\.write|writeText\(|pyperclip\.copy|Set-Clipboard|navigator\.clipboard\.writeText)"), "Writes clipboard contents", "medium"),
    Rule("WALLET_ADDRESS_REPLACE", "HIGH", "clipboard", _rx(r"(?:clipboard|paste)[^\n]{0,180}(?:0x[a-f0-9]{40}|(?:btc|eth|sol|wallet)[_ -]?address)[^\n]{0,180}(?:replace|write|copy)"), "Possible clipboard wallet-address replacement logic", "medium"),
    Rule("WEBHOOK", "MEDIUM", "network", _rx(r"(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|api\.telegram\.org/bot)"), "Webhook or bot endpoint present", "high"),
    Rule("OUTBOUND_POST", "LOW", "network", _rx(r"(?:requests\.post|axios\.post|fetch\s*\(|http\.post|https\.request|urllib\.request|curl\s+[^\n]*(?:-d|--data)|Invoke-WebRequest|Invoke-RestMethod)"), "Outbound HTTP/network operation present", "medium"),
    Rule("RAW_SOCKET", "MEDIUM", "network", _rx(r"(?:socket\.socket|net\.Socket|TcpClient|WebSocket\s*\()"), "Raw socket or websocket communication present", "medium"),
    Rule("BASE64_EXEC", "HIGH", "obfuscation", _rx(r"(?:eval|exec|Function)\s*\([^\n]{0,120}(?:b64decode|atob|fromCharCode|base64)"), "Decoded/obfuscated content appears to be executed", "high"),
    Rule("EVAL_EXEC", "MEDIUM", "obfuscation", _rx(r"\b(?:eval|exec)\s*\("), "Dynamic code execution present", "medium"),
    Rule("SHELL_DOWNLOAD_EXEC", "HIGH", "install-execution", _rx(r"(?:curl|wget)[^\n|;]{0,220}(?:\||;|&&)\s*(?:bash|sh|zsh|python|node)|(?:iwr|Invoke-WebRequest)[^\n]{0,220}(?:iex|Invoke-Expression)"), "Downloads content and executes it in one chain", "high"),
    Rule("POWERSHELL_ENCODED", "HIGH", "obfuscation", _rx(r"powershell(?:\.exe)?[^\n]{0,120}-(?:enc|encodedcommand)\b"), "PowerShell encoded command execution", "high"),
    Rule("UNLIMITED_APPROVAL", "HIGH", "wallet-permission", _rx(r"(?:approve|allowance|permit)[^\n]{0,180}(?:MaxUint256|MAX_UINT|2\s*\*\*\s*256\s*-\s*1|0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)"), "Possible unlimited token approval/permit", "medium"),
    Rule("SIGN_TX", "MEDIUM", "wallet-transaction", _rx(r"(?:signTransaction|sendTransaction|sendRawTransaction|eth_sendTransaction|wallet\.sendTransaction|signAndSendTransaction)"), "Code can sign or submit blockchain transactions", "medium"),
    Rule("ENV_SECRET_READ", "LOW", "credential-access", _rx(r"(?:process\.env|os\.environ|getenv\(|env::var)[^\n]{0,100}(?:PRIVATE_KEY|SEED|MNEMONIC|PASSWORD|TOKEN|SECRET|COOKIE|API_KEY)"), "Reads a sensitive environment variable", "medium"),
    Rule("BROWSER_STORAGE_TOKEN", "MEDIUM", "credential-access", _rx(r"(?:localStorage|sessionStorage|document\.cookie)[^\n]{0,120}(?:token|auth|session|key|wallet)"), "Reads or writes sensitive browser storage", "medium"),
    Rule("WORKFLOW_SECRET_SHELL", "HIGH", "ci-security", _rx(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}[^\n]{0,220}(?:curl|wget|Invoke-WebRequest|nc\s|ssh\s)"), "GitHub Actions secret may be passed to a network-capable command", "medium", True),
)

SENSITIVE_SOURCE = _rx(r"(?:private[_ -]?key|secret[_ -]?key|seed[_ -]?phrase|mnemonic|password|passphrase|api[_ -]?key|auth[_ -]?token|session[_ -]?cookie|document\.cookie|clipboard|process\.env[^\n]*(?:KEY|SECRET|TOKEN|PASSWORD|MNEMONIC|SEED))")
NETWORK_SINK = _rx(r"(?:requests\.post|axios\.post|fetch\s*\(|http\.post|https\.request|webhook|api\.telegram\.org|discord(?:app)?\.com/api/webhooks|socket\.send|sendall\(|curl\s|Invoke-RestMethod|Invoke-WebRequest)")
INSTALL_HOOK = _rx(r'"(?:preinstall|postinstall|prepare)"\s*:\s*"([^"]+)"')
SUSPICIOUS_INSTALL = _rx(r"(?:curl|wget|powershell|Invoke-WebRequest|bash\s+-c|sh\s+-c|node\s+-e|python\s+-c)")
GIT_DEP = _rx(r'"[^"\n]+"\s*:\s*"(?:git\+|https?://|github:)[^"]+"')
UNPINNED_PIP = _rx(r"^[A-Za-z0-9_.-]+\s*(?:$|[><~=!]=?\s*[^\s]+)")


def is_text_candidate(path: str, size: int, max_size: int = 1_000_000) -> bool:
    if size <= 0 or size > max_size:
        return False
    p = PurePosixPath(path)
    if any(part in SKIP_DIRS for part in p.parts):
        return False
    if p.name in {"Dockerfile", "Makefile", "Procfile", "requirements.txt", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "Gemfile", "Gemfile.lock"}:
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


def _finding_from_match(rule: Rule, repository: str, path: str, text: str, match: re.Match[str]) -> Finding:
    line_no = _line_number(text, match.start())
    line_text = text.splitlines()[line_no - 1] if text.splitlines() else ""
    return Finding(
        rule.rule_id,
        rule.severity,
        rule.category,
        repository,
        path,
        line_no,
        rule.summary,
        _redact(line_text, rule.redact_all),
        rule.confidence,
    )


def scan_text(repository: str, path: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for rule in RULES:
        for match in rule.pattern.finditer(text):
            key = (rule.rule_id, _line_number(text, match.start()))
            if key in seen:
                continue
            seen.add(key)
            findings.append(_finding_from_match(rule, repository, path, text, match))
            if sum(1 for f in findings if f.rule_id == rule.rule_id) >= 8:
                break

    # Cross-signal correlation is intentionally stronger than keyword matching.
    source_matches = list(SENSITIVE_SOURCE.finditer(text))
    sink_matches = list(NETWORK_SINK.finditer(text))
    if source_matches and sink_matches:
        for source in source_matches[:4]:
            source_line = _line_number(text, source.start())
            nearest = min(sink_matches, key=lambda m: abs(_line_number(text, m.start()) - source_line))
            sink_line = _line_number(text, nearest.start())
            distance = abs(source_line - sink_line)
            severity = "CRITICAL" if distance <= 40 else "HIGH"
            rule_id = "SECRET_TO_NETWORK" if severity == "CRITICAL" else "SENSITIVE_DATA_WITH_NETWORK"
            key = (rule_id, source_line)
            if key not in seen:
                seen.add(key)
                findings.append(
                    Finding(
                        rule_id,
                        severity,
                        "possible-exfiltration",
                        repository,
                        path,
                        source_line,
                        f"Sensitive-data source and outbound network sink appear in the same file ({distance} lines apart)",
                        "[REDACTED SENSITIVE FLOW CONTEXT]",
                        "high" if distance <= 20 else "medium",
                    )
                )

    lower_name = PurePosixPath(path).name.lower()
    if lower_name == "package.json":
        try:
            package = json.loads(text)
            scripts = package.get("scripts") or {}
            for hook in ("preinstall", "postinstall", "prepare"):
                command = str(scripts.get(hook, ""))
                if command and SUSPICIOUS_INSTALL.search(command):
                    findings.append(
                        Finding(
                            "DANGEROUS_INSTALL_HOOK",
                            "CRITICAL" if hook in {"preinstall", "postinstall"} else "HIGH",
                            "install-execution",
                            repository,
                            path,
                            1,
                            f"{hook} script downloads or executes external/dynamic content",
                            _redact(command),
                            "high",
                        )
                    )
            deps = {}
            deps.update(package.get("dependencies") or {})
            deps.update(package.get("devDependencies") or {})
            for name, spec in list(deps.items())[:500]:
                if isinstance(spec, str) and re.match(r"^(?:git\+|https?://|github:)", spec):
                    findings.append(
                        Finding(
                            "REMOTE_CODE_DEPENDENCY",
                            "MEDIUM",
                            "dependency",
                            repository,
                            path,
                            1,
                            f"Dependency {name!r} installs directly from a remote URL/VCS source",
                            f"{name}: [REMOTE SPEC]",
                            "high",
                        )
                    )
        except json.JSONDecodeError:
            findings.append(Finding("INVALID_PACKAGE_JSON", "LOW", "hygiene", repository, path, 1, "package.json is not valid JSON", "", "high"))

    if lower_name in {"requirements.txt", "requirements-dev.txt"}:
        for index, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if " @ http" in line or line.startswith(("git+", "http://", "https://")):
                findings.append(Finding("REMOTE_PYTHON_DEPENDENCY", "MEDIUM", "dependency", repository, path, index, "Python dependency is installed directly from a remote URL/VCS source", _redact(line), "high"))
            elif re.fullmatch(r"[A-Za-z0-9_.-]+", line):
                findings.append(Finding("UNPINNED_PYTHON_DEPENDENCY", "LOW", "dependency", repository, path, index, "Python dependency is completely unpinned", _redact(line), "high"))

    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.path, f.line, f.rule_id))


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, int, str], Finding] = {}
    for finding in findings:
        key = (finding.repository, finding.path, finding.line, finding.rule_id)
        unique[key] = finding
    return sorted(unique.values(), key=lambda f: (-SEVERITY_RANK[f.severity], f.repository, f.path, f.line))
