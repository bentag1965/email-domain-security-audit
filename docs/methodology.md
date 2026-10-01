# Methodology

## Purpose

The audit evaluates publicly observable controls used to reduce email spoofing and improve mail-domain trust.

## Severity Model

- **Critical** — severe configuration that can materially weaken sender authorization.
- **High** — major control is missing or non-enforcing.
- **Medium** — control exists but is weaker than recommended or requires review.
- **Low** — hardening opportunity or minor concern.
- **Info** — observed configuration without an implied defect.

## Assessment Philosophy

The tool separates three questions:

1. Does a control exist?
2. Does the published policy meaningfully enforce behavior?
3. How certain can we be from public DNS alone?

For example, DMARC with `p=none` is present, but it is monitoring-only rather than enforcing.

## Evidence

Each finding includes the control, severity, title, evidence, and remediation guidance.
