# Contributing to GitHub Trust Auditor

Thanks for helping improve GitHub Trust Auditor.

## Good contributions

Useful contributions include:

- reducing false positives and false negatives,
- adding well-scoped static-analysis rules,
- improving bilingual UX,
- improving rate-limit handling and caching,
- adding tests for new security patterns,
- improving documentation and reproducible examples,
- accessibility and mobile-layout fixes.

## Before opening a pull request

1. Keep target-code analysis **static and defensive**. Do not execute code from scanned repositories.
2. Never add real private keys, seed phrases, access tokens, passwords or other live secrets to tests or fixtures.
3. Add or update tests for behavior changes.
4. Keep security labels evidence-based and avoid claims about a person's identity or intent.
5. Preserve the English/Persian interface when changing user-visible copy.

## Local setup

```bash
git clone https://github.com/SamAlpha1/GitHubTrustAuditor.git
cd GitHubTrustAuditor
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the test suite and syntax checks used by CI before submitting changes.

## Pull request checklist

- [ ] The change has a clear purpose.
- [ ] No live secrets are present.
- [ ] Target code is never executed.
- [ ] Tests cover the change where applicable.
- [ ] User-facing behavior is documented.
- [ ] Security wording is proportional to the evidence.

## Security reports

Do not post sensitive security details publicly when they could expose a real credential or create immediate harm. Follow [`SECURITY.md`](SECURITY.md).

## Maintainer

GitHub: [SamAlpha1](https://github.com/SamAlpha1)  
X: [@samalpha_](https://x.com/samalpha_)
