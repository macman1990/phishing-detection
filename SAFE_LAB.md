# Safe-Lab Guidance — PhishGuard

## Purpose and verification status

This file describes precautions for operating the PhishGuard project. It is not evidence that the application is sandboxed or that a particular workstation, virtual machine, dataset, or API key has been independently verified. The application itself does not enforce isolation, outbound-network restrictions, or sample-retention policies.

## Network behavior in the current code

- Email analysis sends extracted URLs to VirusTotal and URLhaus. VirusTotal may submit a URL for scanning when no prior result is available.
- The advanced email analyzer makes a direct HTTP request to the first extracted URL, follows redirects, and currently disables TLS certificate verification for that request.
- Domain-age and reverse-DNS checks can make WHOIS/DNS lookups.
- The standalone URL Checker sends the entered URL to VirusTotal, URLhaus, PhishTank, and Google Safe Browsing. Its local rule analysis does not itself fetch the URL.
- URL strings may contain sensitive query parameters or internal identifiers. Treat all external lookups as disclosure of that URL to a third party.

Therefore, the earlier statement that URLs are “never visited directly” is not accurate for the current email-analysis path. Use an isolated VM or equivalent disposable environment with restricted egress, and do not submit private, internal, or real victim data without authorization. The project does not configure those controls for you.

## Sample and data handling

- `data/test.eml` is an illustrative phishing-style sample tracked in the repository. It contains sample sender/recipient fields and an example URL; do not assume that any sample or dataset is guaranteed to be free of real-world indicators solely because it is labeled a test.
- Do not execute attachments. The parser extracts attachment metadata and the advanced analyzer evaluates extension/name patterns; it does not provide safe malware detonation.
- Store `.env`, model artifacts, alert history, generated PDFs, and any real samples locally with appropriate access controls. `.env`, `data/model.pkl`, `data/phishing_raw.csv`, the SIEM log, and generated PDFs are excluded by `.gitignore`.
- `reports/siem_alerts.log` may contain sender addresses, subjects, URLs, and flags. The dashboard uses it for alert history; preserve or securely dispose of it according to the data owner's policy.
- Dataset download scripts make outbound requests and may overwrite local dataset files. Review them and back up data before running them.

## Credentials and external services

Keep API keys in a local, untracked `.env` file. Never paste keys into source, reports, screenshots, or issue trackers. Check provider terms and the data-handling implications before enabling VirusTotal or Google Safe Browsing. The code has no credential-rotation mechanism; key rotation must be done through the provider.

## Operational constraints

- The default SIEM destination is UDP `localhost:514`; a successful send call is not confirmation of receipt.
- There is no application-level authentication, authorization, tenant isolation, or egress policy. Do not expose the dashboard as a public service.
- The current code uses custom HTML rendering in Streamlit; do not treat it as hardened against arbitrary untrusted input.
- If a provider or lookup fails, some scores may be zero/unknown. “Clean” should not be inferred from missing or failed intelligence results.

## Safe operating checklist

1. Use a disposable, isolated environment with explicitly approved outbound destinations.
2. Use synthetic or explicitly authorized samples; redact confidential values and URL query secrets.
3. Disable external lookups unless the data owner approves disclosure.
4. Do not open or execute suspicious links or attachments manually.
5. Protect local logs, PDFs, model files, and datasets; do not commit them without review.
6. Confirm API-provider and SIEM configuration before running analyses.
7. Treat results as triage signals that require analyst review, not as automatic containment decisions.

The current repository has not been independently assessed for legal, compliance, privacy, or production-readiness requirements.
