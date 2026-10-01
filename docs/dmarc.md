# DMARC

DMARC builds on SPF and DKIM by adding alignment and a domain-level handling policy.

Record location:

```text
_dmarc.example.com
```

Common policies:

- `p=none` — monitoring only
- `p=quarantine` — suspicious handling requested
- `p=reject` — rejection requested

A staged rollout commonly moves from monitoring to quarantine and then reject after legitimate senders are aligned.
