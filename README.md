# Email Domain Security Audit

A defensive PowerShell utility for assessing the public DNS and email-authentication posture of a domain.

## Executive Lens

Email security is a good example of where a small technical control can have an outsized operational effect. This project turns public DNS and mail-authentication records into structured findings that can be reviewed, prioritized, and remediated rather than checked manually one record at a time.

**Leadership questions this work addresses:**

- Can we tell whether a domain is configured to resist spoofing?
- Are the controls merely present, or are they likely to be enforceable and maintainable?
- Can findings be expressed in a way that supports remediation and audit evidence?
- Where are the limits of what can be concluded from passive public data?

The project checks SPF, DMARC, DKIM selectors, MX records, and basic DNS resolution, then produces structured findings with severity, evidence, and remediation guidance.

## What This Project Demonstrates

- Defensive security automation
- DNS and email-authentication analysis
- SPF policy review
- DMARC enforcement assessment
- DKIM selector probing
- MX and address-record inspection
- MTA-STS discovery
- TLS-RPT discovery
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

## Tradeoffs and Decisions

- **Passive DNS assessment only:** safe and non-intrusive, while intentionally limiting conclusions about the full mail environment.
- **Structured severity and evidence:** supports prioritization and review, but requires conservative findings to avoid overstating risk.
- **Selector probing for DKIM:** useful for known/common selectors, while acknowledging that undiscovered selectors may still exist.

## What I Would Improve Next

I would add SPF lookup-chain counting, include expansion, batch-domain analysis, BIMI discovery, richer HTML/CSV reporting, Pester tests, and optional alignment checks against known sender inventories. In a production setting, I would pair this with DMARC aggregate-report analysis so configuration and observed sending behavior can be reviewed together.

## Planned Enhancements

- SPF DNS-lookup counting
- SPF include-chain inspection
- BIMI discovery
- CSV/HTML reporting
- batch domain input
- Pester tests

## Additional Documentation

- [Assessment methodology](docs/methodology.md)
- [SPF](docs/spf.md)
- [DMARC](docs/dmarc.md)
- [DKIM](docs/dkim.md)
- [Mail transport security](docs/transport-security.md)
