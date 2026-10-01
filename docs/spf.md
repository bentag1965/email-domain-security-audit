# SPF

Sender Policy Framework publishes which systems are authorized to send mail for a domain.

SPF is published as a TXT record at the root domain.

Example:

```text
v=spf1 include:_spf.example.net -all
```

Common terminal mechanisms:

- `-all` — hard fail
- `~all` — soft fail
- `?all` — neutral
- `+all` — allow all and generally unsafe

A domain should publish only one SPF record beginning with `v=spf1`.
