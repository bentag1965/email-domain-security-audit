# Email Domain Security Audit

A defensive PowerShell utility for assessing the public DNS and email-authentication posture of a domain.

The project checks SPF, DMARC, DKIM selectors, MX records, and basic DNS resolution, then produces structured findings with severity, evidence, and remediation guidance.

## What This Project Demonstrates

- Defensive security automation
- DNS and email-authentication analysis
- SPF policy review
- DMARC enforcement assessment
- DKIM selector probing
- MX and address-record inspection
- Structured JSON reporting
- PowerShell security tooling

## Example

```powershell
.\src\Invoke-EmailDomainSecurityAudit.ps1 -Domain example.com -DkimSelectors selector1,selector2,google,default -OutputJson .\reports\example.com.json
```

## Security Scope

This utility performs passive DNS queries against public records. It does not attempt authentication, mailbox access, credential testing, exploitation, or intrusive scanning.

## Repository Layout

```text
email-domain-security-audit/
├── docs/
│   ├── methodology.md
│   ├── spf.md
│   ├── dmarc.md
│   └── dkim.md
├── src/
│   └── Invoke-EmailDomainSecurityAudit.ps1
├── examples/
│   └── sample-report.json
├── .gitignore
└── README.md
```

## Important Limitations

A public DNS audit cannot prove that an entire email environment is secure. A strong DMARC record does not prove every legitimate sender is aligned, DKIM selectors may be unknown, and SPF can be present but operationally broken.

## Planned Enhancements

- SPF DNS-lookup counting
- SPF include-chain inspection
- MTA-STS detection
- TLS-RPT detection
- BIMI discovery
- CSV/HTML reporting
- batch domain input
- Pester tests
