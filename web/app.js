const state = {
  lang: (navigator.language || "").toLowerCase().startsWith("fa") ? "fa" : "en",
  report: null,
  loadingTimer: null,
};

const T = {
  en: {
    eyebrow: "DEFENSIVE GITHUB SECURITY CHECK",
    title: "Check a GitHub account before you trust its code.",
    subtitle: "Paste a username, profile URL, or repository URL. The auditor checks public repositories for credential theft, secret exfiltration, dangerous wallet behavior, install hooks, obfuscation, repository quality, and contribution activity.",
    inputLabel: "GitHub username or URL",
    scan: "SCAN GITHUB",
    helper: "Read-only scan. Never enter a seed phrase, private key, or password.",
    securityWeight: "Security signals",
    hygieneWeight: "Repository hygiene",
    historyWeight: "History & reputation",
    contributionWeight: "Contribution graph",
    scanning: "Scanning GitHub account…",
    stageRepos: "Discovering repositories and account history",
    stageCode: "Scanning code for secrets, credential collection, and exfiltration",
    stageWallet: "Reviewing wallet permissions, transactions, install hooks, and obfuscation",
    stageHistory: "Scoring repository quality and contribution activity",
    scanFailed: "Scan failed",
    auditedAccount: "AUDITED ACCOUNT",
    openProfile: "Open GitHub ↗",
    publicRepos: "Public repos",
    followers: "Followers",
    accountAge: "Account age",
    coverage: "Scan coverage",
    scoreBreakdownLabel: "SCORE BREAKDOWN",
    scoreBreakdown: "Why this account got this score",
    security: "Security",
    hygiene: "Repository hygiene",
    history: "History & reputation",
    contributions: "Contribution graph",
    securityRowsLabel: "SECURITY CHECKS",
    securityRows: "Detailed risk table",
    greenSquaresLabel: "CONTRIBUTION GRAPH",
    greenSquares: "GitHub “green squares” activity",
    totalContributions: "Contributions",
    activeDays: "Active days",
    longestStreak: "Longest streak",
    currentStreak: "Current streak",
    repoLabel: "REPOSITORY AUDIT",
    repoTitle: "Repository-by-repository score",
    repo: "Repository",
    repoScore: "Score",
    risk: "Risk",
    stars: "Stars",
    forks: "Forks",
    files: "Files",
    findingsLabel: "FLAGGED EVIDENCE",
    findingsTitle: "Files that need review",
    supportLabel: "CLEAN SCAN",
    supportTitle: "Useful and clean? Support the developer.",
    supportCopy: "No significant malicious indicators were detected in the scanned coverage. If you actually find a project useful, consider starring or forking it on GitHub.",
    important: "Important",
    coverageNote: "This is static technical analysis, not proof that a person is honest or a scammer. Private third-party repositories cannot be inspected without legitimate access.",
    footer: "Defensive, read-only analysis",
    open: "Open",
    star: "Star",
    fork: "Fork",
    years: "yr",
    complete: "Complete",
    partial: "Partial",
    unavailable: "Unavailable",
    findings: "findings",
    noFindings: "No suspicious signal detected in this category",
    review: "Review flagged evidence",
    exactGraph: "The green-square panel uses contribution dates/counts returned by GitHub when available. Contribution activity is only 8% of the score and can never override serious security findings.",
    uniformGraph: "Contribution counts are unusually uniform. This is informational only and is not evidence of wrongdoing.",
    graphUnavailable: "GitHub contribution calendar was unavailable, so no activity points were awarded.",
    trustedTitle: "TRUSTED • CLEAN SIGNALS",
    trustedMsg: "No significant malicious indicators were detected in the scanned coverage. Still review important code before running it.",
    lowTitle: "LOW RISK",
    lowMsg: "No critical indicator was detected, but some quality or low-level risk signals deserve review.",
    cautionTitle: "CAUTION • REVIEW REQUIRED",
    cautionMsg: "Meaningful warning signals were found. Review the flagged files before installing, running code, or connecting a wallet.",
    highTitle: "SEVERE RISK • POSSIBLE SCAM BEHAVIOR",
    highMsg: "Serious security indicators were found. Do not run flagged code or provide wallet/authentication secrets until independently reviewed.",
    criticalTitle: "CRITICAL SCAM RISK",
    criticalMsg: "Critical credential-theft, secret-exfiltration, or dangerous execution indicators were detected. DO NOT RUN. DO NOT CONNECT A WALLET. DO NOT ENTER SECRETS.",
    signalTrusted: "SAFE SIGNAL",
    signalLow: "LOW-RISK SIGNAL",
    signalCaution: "WARNING",
    signalHigh: "SEVERE WARNING",
    signalCritical: "🚨 CRITICAL SECURITY ALARM 🚨",
    statusOk: "OK",
    statusLow: "LOW",
    statusMedium: "CAUTION",
    statusHigh: "HIGH",
    statusCritical: "CRITICAL",
    credentialsTitle: "Seed / private key / password theft",
    credentialsDetail: "Secret prompts, sensitive literals, environment access, credential collection",
    exfilTitle: "Data exfiltration & webhooks",
    exfilDetail: "Sensitive data flowing to HTTP, Telegram, Discord, webhooks, or sockets",
    clipboardTitle: "Clipboard & wallet-address replacement",
    clipboardDetail: "Clipboard reads/writes and crypto-address replacement patterns",
    walletTitle: "Wallet approvals & transactions",
    walletDetail: "Unlimited approvals, signing, sending, and undocumented transaction capability",
    installTitle: "Install scripts & obfuscation",
    installDetail: "postinstall/preinstall, download-and-execute, eval/exec, encoded commands",
    dependencyTitle: "Dependencies & CI security",
    dependencyDetail: "Remote dependencies and GitHub Actions secret/permission risks",
    hygieneTitle: "Documentation & repository hygiene",
    hygieneDetail: "README, license, SECURITY.md, CI, and complete scan coverage",
    contributionTitle: "Contribution graph signal",
    contributionDetail: "Active days, streaks, total contributions, and suspicious uniformity",
  },
  fa: {
    eyebrow: "بررسی دفاعی امنیت گیت‌هاب",
    title: "قبل از اعتماد به کد، اکانت GitHub را بررسی کن.",
    subtitle: "نام کاربری، لینک پروفایل یا لینک یکی از ریپوها را وارد کن. ابزار ریپوهای عمومی را از نظر سرقت سید و کلید خصوصی، خروج اطلاعات، رفتار خطرناک کیف پول، اسکریپت نصب، مبهم‌سازی کد، کیفیت ریپو و فعالیت Contribution بررسی می‌کند.",
    inputLabel: "نام کاربری یا لینک GitHub",
    scan: "بررسی کامل گیت‌هاب",
    helper: "اسکن فقط خواندنی است. هیچ‌وقت سید، کلید خصوصی یا پسورد را اینجا وارد نکن.",
    securityWeight: "سیگنال‌های امنیتی",
    hygieneWeight: "سلامت ریپوها",
    historyWeight: "سابقه و اعتبار",
    contributionWeight: "چمن‌های سبز",
    scanning: "در حال بررسی اکانت GitHub…",
    stageRepos: "در حال پیدا کردن ریپوها و سابقه اکانت",
    stageCode: "در حال بررسی کد برای سرقت اطلاعات، کلیدها و خروج مخفیانه داده",
    stageWallet: "در حال بررسی دسترسی کیف پول، تراکنش‌ها، اسکریپت‌های نصب و کدهای مبهم",
    stageHistory: "در حال امتیازدهی کیفیت ریپو و فعالیت چمن‌های سبز",
    scanFailed: "بررسی ناموفق بود",
    auditedAccount: "اکانت بررسی‌شده",
    openProfile: "باز کردن GitHub ↗",
    publicRepos: "ریپوی عمومی",
    followers: "دنبال‌کننده",
    accountAge: "سن اکانت",
    coverage: "پوشش اسکن",
    scoreBreakdownLabel: "جزئیات امتیاز",
    scoreBreakdown: "این امتیاز از کجا آمده؟",
    security: "امنیت",
    hygiene: "سلامت ریپو",
    history: "سابقه و اعتبار",
    contributions: "چمن‌های سبز",
    securityRowsLabel: "بررسی‌های امنیتی",
    securityRows: "جدول دقیق ریسک",
    greenSquaresLabel: "فعالیت GitHub",
    greenSquares: "وضعیت چمن‌های سبز GitHub",
    totalContributions: "Contribution",
    activeDays: "روز فعال",
    longestStreak: "طولانی‌ترین تداوم",
    currentStreak: "تداوم فعلی",
    repoLabel: "بررسی ریپوها",
    repoTitle: "امتیاز تک‌تک ریپازیتوری‌ها",
    repo: "ریپازیتوری",
    repoScore: "امتیاز",
    risk: "ریسک",
    stars: "استار",
    forks: "فورک",
    files: "فایل",
    findingsLabel: "شواهد علامت‌گذاری‌شده",
    findingsTitle: "فایل‌هایی که باید بررسی شوند",
    supportLabel: "اسکن سالم",
    supportTitle: "پروژه مفید و سالم بود؟ از سازنده حمایت کن.",
    supportCopy: "در محدوده اسکن‌شده نشانه مهمی از رفتار مخرب پیدا نشد. اگر واقعاً پروژه برایت مفید است، می‌توانی آن را در GitHub استار یا فورک کنی.",
    important: "مهم",
    coverageNote: "این نتیجه تحلیل فنی و استاتیک است و اثبات نمی‌کند یک شخص حتماً سالم یا اسکمر است. ریپوهای پرایوت اشخاص دیگر بدون دسترسی قانونی قابل بررسی نیستند.",
    footer: "تحلیل دفاعی و فقط خواندنی",
    open: "باز کردن",
    star: "استار",
    fork: "فورک",
    years: "سال",
    complete: "کامل",
    partial: "ناقص",
    unavailable: "ناموجود",
    findings: "هشدار",
    noFindings: "در این بخش سیگنال مشکوکی پیدا نشد",
    review: "شواهد علامت‌گذاری‌شده را بررسی کن",
    exactGraph: "چمن‌های سبز بر اساس تاریخ و تعداد Contribution دریافتی از GitHub نمایش داده می‌شوند. این بخش فقط ۸٪ امتیاز را می‌سازد و هیچ‌وقت هشدار امنیتی جدی را خنثی نمی‌کند.",
    uniformGraph: "الگوی Contribution بیش از حد یکنواخت است. این فقط یک سیگنال اطلاعاتی است و به‌تنهایی نشانه تخلف نیست.",
    graphUnavailable: "تقویم Contribution از GitHub قابل دریافت نبود؛ برای این بخش امتیاز مثبت در نظر گرفته نشد.",
    trustedTitle: "مطمئن • سیگنال‌های سالم",
    trustedMsg: "در محدوده اسکن‌شده نشانه مهمی از رفتار مخرب پیدا نشد. با این حال قبل از اجرا، بخش‌های مهم کد را خودت هم مرور کن.",
    lowTitle: "ریسک پایین",
    lowMsg: "نشانه بحرانی پیدا نشد، اما چند مورد کیفی یا کم‌خطر بهتر است بررسی شوند.",
    cautionTitle: "احتیاط • نیاز به بررسی",
    cautionMsg: "چند هشدار معنادار پیدا شد. قبل از نصب، اجرا یا اتصال کیف پول فایل‌های علامت‌گذاری‌شده را بررسی کن.",
    highTitle: "ریسک شدید • رفتار مشکوک به اسکم",
    highMsg: "نشانه‌های امنیتی جدی پیدا شد. تا بررسی مستقل، کدهای علامت‌گذاری‌شده را اجرا نکن و اطلاعات کیف پول یا احراز هویت وارد نکن.",
    criticalTitle: "ریسک بحرانی اسکم",
    criticalMsg: "نشانه‌های بحرانی سرقت اطلاعات، خروج مخفیانه داده یا اجرای خطرناک شناسایی شد. اجرا نکن؛ کیف پول وصل نکن؛ هیچ راز یا کلیدی وارد نکن.",
    signalTrusted: "سیگنال سالم",
    signalLow: "سیگنال کم‌ریسک",
    signalCaution: "هشدار",
    signalHigh: "هشدار شدید",
    signalCritical: "🚨 آژیر امنیتی بحرانی 🚨",
    statusOk: "سالم",
    statusLow: "کم",
    statusMedium: "احتیاط",
    statusHigh: "شدید",
    statusCritical: "بحرانی",
    credentialsTitle: "سرقت سید، کلید خصوصی یا پسورد",
    credentialsDetail: "درخواست رازها، کلیدهای داخل کد، دسترسی به متغیرهای حساس و جمع‌آوری اعتبارنامه",
    exfilTitle: "خروج اطلاعات و Webhook",
    exfilDetail: "ارسال داده حساس به HTTP، تلگرام، دیسکورد، Webhook یا Socket",
    clipboardTitle: "کلیپ‌بورد و تعویض آدرس کیف پول",
    clipboardDetail: "خواندن/نوشتن کلیپ‌بورد و الگوهای جایگزینی آدرس کریپتو",
    walletTitle: "مجوزها و تراکنش‌های کیف پول",
    walletDetail: "Approve نامحدود، امضا، ارسال تراکنش و قابلیت تراکنش بدون توضیح کافی",
    installTitle: "اسکریپت نصب و مبهم‌سازی کد",
    installDetail: "pre/postinstall، دانلود و اجرا، eval/exec و فرمان‌های Encode شده",
    dependencyTitle: "Dependency و امنیت CI",
    dependencyDetail: "Dependencyهای ریموت و خطرهای Secret/Permission در GitHub Actions",
    hygieneTitle: "مستندات و سلامت ریپو",
    hygieneDetail: "README، لایسنس، SECURITY.md، CI و کامل بودن پوشش اسکن",
    contributionTitle: "سیگنال چمن‌های سبز",
    contributionDetail: "روزهای فعال، تداوم، تعداد Contribution و یکنواختی غیرعادی",
  }
};

const ruleFa = {
  HARDCODED_EVM_KEY: "کلید خصوصی یا راز ۳۲ بایتی احتمالی داخل کد",
  GITHUB_TOKEN_LITERAL: "توکن دسترسی GitHub احتمالی داخل سورس",
  AWS_ACCESS_KEY: "کلید دسترسی AWS احتمالی داخل سورس",
  SLACK_TOKEN: "توکن Slack احتمالی داخل سورس",
  MNEMONIC_ASSIGNMENT: "عبارت شبیه سید یا Mnemonic داخل سورس",
  PRIVATE_KEY_PROMPT: "کد از کاربر کلید خصوصی، سید یا Mnemonic می‌خواهد",
  PASSWORD_PROMPT: "کد اطلاعات حساس احراز هویت از کاربر می‌خواهد",
  CLIPBOARD_READ: "کد محتوای کلیپ‌بورد را می‌خواند",
  CLIPBOARD_WRITE: "کد محتوای کلیپ‌بورد را تغییر می‌دهد",
  WALLET_ADDRESS_REPLACE: "الگوی احتمالی جایگزینی آدرس کیف پول در کلیپ‌بورد",
  WEBHOOK: "Webhook یا Bot endpoint در کد وجود دارد",
  OUTBOUND_POST: "عملیات خروجی شبکه/HTTP در کد وجود دارد",
  RAW_SOCKET: "ارتباط Socket یا WebSocket وجود دارد",
  BASE64_EXEC: "محتوای Decode/مبهم‌شده اجرا می‌شود",
  EVAL_EXEC: "اجرای پویای کد با eval/exec",
  SHELL_DOWNLOAD_EXEC: "دانلود و اجرای مستقیم محتوا در یک زنجیره",
  POWERSHELL_ENCODED: "اجرای فرمان Encode شده PowerShell",
  UNLIMITED_APPROVAL: "Approve یا Permit نامحدود احتمالی توکن",
  SIGN_TX: "کد قابلیت امضا یا ارسال تراکنش دارد",
  ENV_SECRET_READ: "خواندن متغیر محیطی حساس",
  BROWSER_STORAGE_TOKEN: "دسترسی به داده حساس مرورگر یا Session",
  WORKFLOW_SECRET_SHELL: "Secret در GitHub Actions ممکن است در دستور شبکه استفاده شود",
  SECRET_TO_NETWORK: "داده حساس و مسیر خروج شبکه در فاصله نزدیک شناسایی شد",
  SENSITIVE_DATA_WITH_NETWORK: "داده حساس و خروج شبکه در یک فایل وجود دارد",
  DANGEROUS_INSTALL_HOOK: "اسکریپت نصب محتوای خارجی یا پویا را اجرا می‌کند",
  REMOTE_CODE_DEPENDENCY: "Dependency مستقیماً از URL یا VCS نصب می‌شود",
  INVALID_PACKAGE_JSON: "فایل package.json معتبر نیست",
  REMOTE_PYTHON_DEPENDENCY: "Dependency پایتون مستقیماً از URL/VCS نصب می‌شود",
  UNPINNED_PYTHON_DEPENDENCY: "نسخه Dependency پایتون قفل نشده است",
  UNDOCUMENTED_TRANSACTION_CAPABILITY: "قابلیت تراکنش/امضا در README به‌وضوح توضیح داده نشده",
  SENSITIVE_FILENAME_COMMITTED: "فایلی با نام حساس داخل ریپو Commit شده است",
};

const severityRank = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

const rowDefinitions = [
  {
    icon: "🔑", title: "credentialsTitle", detail: "credentialsDetail",
    match: f => ["secret-exposure", "credential-collection", "credential-access", "possible-exfiltration"].includes(f.category)
  },
  {
    icon: "⇧", title: "exfilTitle", detail: "exfilDetail",
    match: f => ["network", "possible-exfiltration"].includes(f.category) || ["SECRET_TO_NETWORK", "SENSITIVE_DATA_WITH_NETWORK", "WEBHOOK"].includes(f.rule_id)
  },
  {
    icon: "▣", title: "clipboardTitle", detail: "clipboardDetail",
    match: f => f.category === "clipboard"
  },
  {
    icon: "◈", title: "walletTitle", detail: "walletDetail",
    match: f => ["wallet-permission", "wallet-transaction", "documentation-mismatch"].includes(f.category)
  },
  {
    icon: "⚙", title: "installTitle", detail: "installDetail",
    match: f => ["install-execution", "obfuscation"].includes(f.category)
  },
  {
    icon: "⌘", title: "dependencyTitle", detail: "dependencyDetail",
    match: f => ["dependency", "ci-security"].includes(f.category)
  },
];

const $ = selector => document.querySelector(selector);

function tr(key) {
  return T[state.lang][key] ?? T.en[key] ?? key;
}

function applyLanguage() {
  document.documentElement.lang = state.lang;
  document.documentElement.dir = state.lang === "fa" ? "rtl" : "ltr";
  $("#langToggle").textContent = state.lang === "fa" ? "EN" : "FA";
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const key = el.dataset.i18n;
    if (T[state.lang][key]) el.textContent = T[state.lang][key];
  });
  $("#targetInput").placeholder = state.lang === "fa"
    ? "SamAlpha1 یا https://github.com/SamAlpha1"
    : "octocat or https://github.com/octocat";
  if (state.report) renderReport(state.report, false);
}

function allFindings(report) {
  return (report.repositories || []).flatMap(repo =>
    (repo.findings || []).map(finding => ({ ...finding, repo_score: repo.repo_score }))
  );
}

function maxSeverity(findings) {
  let best = "INFO";
  for (const finding of findings) {
    if ((severityRank[finding.severity] ?? 0) > (severityRank[best] ?? 0)) best = finding.severity;
  }
  return best;
}

function severityClass(severity) {
  if (severity === "CRITICAL") return "pill-critical";
  if (severity === "HIGH") return "pill-high";
  if (severity === "MEDIUM") return "pill-medium";
  if (severity === "LOW") return "pill-low";
  return "pill-ok";
}

function severityText(severity) {
  const key = {
    CRITICAL: "statusCritical",
    HIGH: "statusHigh",
    MEDIUM: "statusMedium",
    LOW: "statusLow",
    INFO: "statusOk",
  }[severity] || "statusOk";
  return tr(key);
}

function verdictClass(verdict) {
  return {
    TRUSTED: "trusted",
    "LOW RISK": "low",
    CAUTION: "caution",
    "HIGH RISK": "high",
    CRITICAL: "critical",
  }[verdict] || "caution";
}

function verdictCopy(verdict) {
  const map = {
    TRUSTED: ["trustedTitle", "trustedMsg", "signalTrusted"],
    "LOW RISK": ["lowTitle", "lowMsg", "signalLow"],
    CAUTION: ["cautionTitle", "cautionMsg", "signalCaution"],
    "HIGH RISK": ["highTitle", "highMsg", "signalHigh"],
    CRITICAL: ["criticalTitle", "criticalMsg", "signalCritical"],
  };
  const keys = map[verdict] || map.CAUTION;
  return keys.map(tr);
}

function ageFromDate(raw) {
  if (!raw) return "—";
  const created = new Date(raw);
  if (Number.isNaN(created.getTime())) return "—";
  const years = Math.max(0, (Date.now() - created.getTime()) / (365.25 * 86400000));
  return `${years < 1 ? years.toFixed(1) : Math.floor(years)} ${tr("years")}`;
}

function formatNumber(value) {
  return new Intl.NumberFormat(state.lang === "fa" ? "fa-IR" : "en-US").format(Number(value || 0));
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderRiskRows(report, findings) {
  const container = $("#riskRows");
  const rows = rowDefinitions.map(def => {
    const hits = findings.filter(def.match);
    const severity = hits.length ? maxSeverity(hits) : "INFO";
    return riskRowHtml(def.icon, tr(def.title), tr(def.detail), severity, hits.length);
  });

  const hygiene = Number(report.score?.hygiene || 0);
  const hygieneSeverity = report.coverage?.partial ? "MEDIUM" : hygiene >= 16 ? "INFO" : hygiene >= 10 ? "LOW" : "MEDIUM";
  rows.push(riskRowHtml("✓", tr("hygieneTitle"), tr("hygieneDetail"), hygieneSeverity, `${hygiene}/20`));

  const contribution = report.contributions || {};
  const contributionSeverity = !contribution.available
    ? "LOW"
    : contribution.suspicious_uniformity ? "MEDIUM" : "INFO";
  rows.push(riskRowHtml("▦", tr("contributionTitle"), tr("contributionDetail"), contributionSeverity, `${report.score?.contributions || 0}/8`));

  container.innerHTML = rows.join("");
}

function riskRowHtml(icon, title, detail, severity, count) {
  const countText = typeof count === "number" ? `${formatNumber(count)} ${tr("findings")}` : count;
  const detailText = typeof count === "number" && count === 0 ? `${detail} • ${tr("noFindings")}` : detail;
  return `
    <div class="risk-row">
      <div class="risk-row-title">
        <span class="risk-row-icon">${escapeHtml(icon)}</span>
        <div><strong>${escapeHtml(title)}</strong><small>${escapeHtml(detailText)}</small></div>
      </div>
      <span class="status-pill ${severityClass(severity)}">${escapeHtml(severityText(severity))}</span>
      <span class="risk-row-count">${escapeHtml(countText)}</span>
    </div>
  `;
}

function repoSeverity(repo) {
  const findings = repo.findings || [];
  if (findings.length) return maxSeverity(findings);
  if (!repo.complete) return "MEDIUM";
  if (repo.repo_score < 40) return "HIGH";
  if (repo.repo_score < 70) return "MEDIUM";
  if (repo.repo_score < 85) return "LOW";
  return "INFO";
}

function renderRepos(report) {
  const repos = [...(report.repositories || [])].sort((a, b) =>
    (a.repo_score - b.repo_score) || ((b.stars || 0) - (a.stars || 0))
  );
  $("#repoCountBadge").textContent = formatNumber(repos.length);
  $("#repoTableBody").innerHTML = repos.map(repo => {
    const severity = repoSeverity(repo);
    const url = `https://github.com/${encodeURI(repo.full_name)}`;
    return `
      <tr>
        <td><div class="repo-name" title="${escapeHtml(repo.full_name)}">${escapeHtml(repo.full_name)}</div></td>
        <td><span class="repo-score-number">${escapeHtml(repo.repo_score)}</span>/100</td>
        <td><span class="repo-risk ${severityClass(severity)}">${escapeHtml(severityText(severity))}</span></td>
        <td>${formatNumber(repo.stars)}</td>
        <td>${formatNumber(repo.forks)}</td>
        <td>${formatNumber(repo.files_scanned)}${repo.complete ? "" : " *"}</td>
        <td><a class="mini-button" href="${url}" target="_blank" rel="noopener noreferrer">${escapeHtml(tr("open"))} ↗</a></td>
      </tr>
    `;
  }).join("");
}

function renderFindings(report, findings) {
  const section = $("#findingsSection");
  if (!findings.length) {
    section.classList.add("hidden");
    return;
  }
  section.classList.remove("hidden");
  const sorted = [...findings].sort((a, b) =>
    (severityRank[b.severity] ?? 0) - (severityRank[a.severity] ?? 0)
  );
  $("#findingCountBadge").textContent = formatNumber(sorted.length);
  $("#findingList").innerHTML = sorted.slice(0, 80).map(finding => {
    const cls = finding.severity === "CRITICAL" ? "critical" : finding.severity === "HIGH" ? "high" : "";
    const summary = state.lang === "fa" ? (ruleFa[finding.rule_id] || finding.summary) : finding.summary;
    return `
      <article class="finding-card ${cls}">
        <div class="finding-head">
          <strong>${escapeHtml(finding.rule_id)}</strong>
          <span class="severity-pill ${severityClass(finding.severity)}">${escapeHtml(severityText(finding.severity))}</span>
        </div>
        <div class="finding-meta">${escapeHtml(finding.repository)} • ${escapeHtml(finding.path)}:${escapeHtml(finding.line)}</div>
        <p class="finding-summary">${escapeHtml(summary)}</p>
        ${finding.evidence ? `<div class="finding-evidence">${escapeHtml(finding.evidence)}</div>` : ""}
      </article>
    `;
  }).join("");
}

function renderContributions(report) {
  const c = report.contributions || {};
  $("#contribTotal").textContent = c.available ? formatNumber(c.total) : "—";
  $("#activeDays").textContent = c.available ? formatNumber(c.active_days) : "—";
  $("#longestStreak").textContent = c.available ? formatNumber(c.longest_streak) : "—";
  $("#currentStreak").textContent = c.available ? formatNumber(c.current_streak) : "—";

  const heat = $("#heatmap");
  heat.innerHTML = "";
  const byDate = new Map((c.calendar || []).map(item => [item.date, Number(item.count || 0)]));
  const today = new Date();
  const start = new Date(today);
  start.setUTCDate(start.getUTCDate() - 363);
  let maxCount = Math.max(1, ...(c.calendar || []).map(item => Number(item.count || 0)));

  for (let i = 0; i < 364; i++) {
    const date = new Date(start);
    date.setUTCDate(start.getUTCDate() + i);
    const key = date.toISOString().slice(0, 10);
    const count = byDate.get(key) || 0;
    const level = count <= 0 ? 0 : Math.min(4, Math.max(1, Math.ceil((count / maxCount) * 4)));
    const cell = document.createElement("span");
    cell.className = `heat-cell ${level ? `l${level}` : ""}`;
    cell.title = `${key}: ${count}`;
    heat.appendChild(cell);
  }

  if (!c.available) $("#contributionNote").textContent = tr("graphUnavailable");
  else if (c.suspicious_uniformity) $("#contributionNote").textContent = `${tr("uniformGraph")} ${tr("exactGraph")}`;
  else $("#contributionNote").textContent = tr("exactGraph");
}

function renderSupport(report, findings) {
  const card = $("#supportCard");
  const highOrCritical = findings.some(f => ["HIGH", "CRITICAL"].includes(f.severity));
  if (report.score?.verdict !== "TRUSTED" || highOrCritical || report.coverage?.partial) {
    card.classList.add("hidden");
    return;
  }

  const safe = (report.repositories || [])
    .filter(repo => !repo.private && !repo.archived && repo.complete && repo.repo_score >= 85 &&
      !(repo.findings || []).some(f => ["HIGH", "CRITICAL"].includes(f.severity)))
    .sort((a, b) => (b.repo_score - a.repo_score) || ((b.stars || 0) - (a.stars || 0)))
    .slice(0, 3);

  if (!safe.length) {
    card.classList.add("hidden");
    return;
  }

  card.classList.remove("hidden");
  $("#supportButtons").innerHTML = safe.map(repo => {
    const repoUrl = `https://github.com/${encodeURI(repo.full_name)}`;
    const forkUrl = `${repoUrl}/fork`;
    const short = repo.full_name.split("/").pop();
    return `
      <a class="support-button" href="${repoUrl}" target="_blank" rel="noopener noreferrer">⭐ ${escapeHtml(tr("star"))} ${escapeHtml(short)}</a>
      <a class="support-button" href="${forkUrl}" target="_blank" rel="noopener noreferrer">⑂ ${escapeHtml(tr("fork"))} ${escapeHtml(short)}</a>
    `;
  }).join("");
}

function playRiskAlert(verdict) {
  if (!["LOW RISK", "CAUTION", "HIGH RISK", "CRITICAL"].includes(verdict)) return;
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) return;

  const patterns = {
    "LOW RISK": [[440, .08]],
    CAUTION: [[610, .12], [460, .12]],
    "HIGH RISK": [[330, .14], [330, .14], [250, .18]],
    CRITICAL: [[880, .16], [220, .16], [880, .16], [220, .16], [880, .22], [220, .24]],
  };
  const ctx = new AudioCtx();
  let cursor = ctx.currentTime + .03;
  for (const [frequency, duration] of patterns[verdict]) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = verdict === "CRITICAL" ? "sawtooth" : "sine";
    osc.frequency.value = frequency;
    gain.gain.setValueAtTime(.0001, cursor);
    gain.gain.exponentialRampToValueAtTime(verdict === "CRITICAL" ? .16 : .08, cursor + .015);
    gain.gain.exponentialRampToValueAtTime(.0001, cursor + duration);
    osc.connect(gain).connect(ctx.destination);
    osc.start(cursor);
    osc.stop(cursor + duration + .02);
    cursor += duration + .08;
  }
  window.setTimeout(() => ctx.close(), Math.max(1200, (cursor - ctx.currentTime + .2) * 1000));
  if (navigator.vibrate && ["HIGH RISK", "CRITICAL"].includes(verdict)) {
    navigator.vibrate(verdict === "CRITICAL" ? [220, 90, 220, 90, 420] : [180, 80, 180]);
  }
}

function renderReport(report, withAlert = true) {
  state.report = report;
  const findings = allFindings(report);
  const score = report.score || {};
  const verdict = score.verdict || "CAUTION";
  const [title, message, signal] = verdictCopy(verdict);

  const banner = $("#riskBanner");
  banner.className = `risk-banner ${verdictClass(verdict)}`;
  $("#riskSignal").textContent = signal;
  $("#riskTitle").textContent = title;
  $("#riskMessage").textContent = message;
  $("#totalScore").textContent = score.total ?? "—";
  $("#scoreOrb").style.setProperty("--score-angle", `${Math.max(0, Math.min(100, Number(score.total || 0))) * 3.6}deg`);

  const username = report.username || report.profile?.login || "";
  $("#profileAvatar").src = `https://github.com/${encodeURIComponent(username)}.png?size=180`;
  $("#profileAvatar").alt = `${username} GitHub avatar`;
  $("#profileName").textContent = `@${username}`;
  $("#openProfile").href = `https://github.com/${encodeURIComponent(username)}`;
  $("#publicRepos").textContent = formatNumber(report.profile?.public_repos);
  $("#followers").textContent = formatNumber(report.profile?.followers);
  $("#accountAge").textContent = ageFromDate(report.profile?.created_at);
  $("#coverageValue").textContent = report.coverage?.partial ? tr("partial") : tr("complete");

  $("#securityScore").textContent = score.security ?? "—";
  $("#hygieneScore").textContent = score.hygiene ?? "—";
  $("#historyScore").textContent = score.history ?? "—";
  $("#contributionScore").textContent = score.contributions ?? "—";

  renderRiskRows(report, findings);
  renderContributions(report);
  renderRepos(report);
  renderFindings(report, findings);
  renderSupport(report, findings);

  const coverage = report.coverage || {};
  const scanned = coverage.files_scanned ?? (report.repositories || []).reduce((a, r) => a + Number(r.files_scanned || 0), 0);
  const repoCount = (report.repositories || []).length;
  const privateNote = coverage.private_authorized
    ? ` • private repos: ${coverage.private_count || 0}`
    : "";
  $("#coverageNote").textContent =
    `${tr("coverageNote")} ${repoCount} repos / ${scanned} files scanned${privateNote}${coverage.partial ? " • PARTIAL COVERAGE" : ""}.`;

  $("#results").classList.remove("hidden");
  if (withAlert) playRiskAlert(verdict);
  window.setTimeout(() => $("#results").scrollIntoView({ behavior: "smooth", block: "start" }), 120);
}

function startLoading() {
  const stages = ["stageRepos", "stageCode", "stageWallet", "stageHistory"];
  let index = 0;
  $("#loadingStage").textContent = tr(stages[index]);
  state.loadingTimer = window.setInterval(() => {
    index = (index + 1) % stages.length;
    $("#loadingStage").textContent = tr(stages[index]);
  }, 1800);
  $("#loadingPanel").classList.remove("hidden");
}

function stopLoading() {
  if (state.loadingTimer) window.clearInterval(state.loadingTimer);
  state.loadingTimer = null;
  $("#loadingPanel").classList.add("hidden");
}

async function scanTarget(target) {
  $("#errorPanel").classList.add("hidden");
  $("#results").classList.add("hidden");
  $("#scanButton").disabled = true;
  startLoading();

  try {
    const response = await fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    renderReport(payload.report, true);
  } catch (error) {
    $("#errorText").textContent = error?.message || String(error);
    $("#errorPanel").classList.remove("hidden");
  } finally {
    stopLoading();
    $("#scanButton").disabled = false;
  }
}

$("#scanForm").addEventListener("submit", event => {
  event.preventDefault();
  const value = $("#targetInput").value.trim();
  if (value) scanTarget(value);
});

$("#langToggle").addEventListener("click", () => {
  state.lang = state.lang === "fa" ? "en" : "fa";
  localStorage.setItem("gta-language", state.lang);
  applyLanguage();
});

const savedLanguage = localStorage.getItem("gta-language");
if (savedLanguage === "fa" || savedLanguage === "en") state.lang = savedLanguage;
applyLanguage();
