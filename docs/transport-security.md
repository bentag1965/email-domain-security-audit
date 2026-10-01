# Mail Transport Security

## MTA-STS

MTA-STS lets a receiving domain publish a policy telling sending mail systems to require TLS when delivering mail.

The DNS discovery record is published at:

```text
_mta-sts.example.com
```

with a TXT value beginning:

```text
v=STSv1;
```

A complete deployment also requires an HTTPS policy file at the domain's MTA-STS policy host. This reference tool checks the DNS discovery record only.

## TLS-RPT

TLS Reporting lets a domain receive aggregate reports about transport-layer delivery failures.

The record is published at:

```text
_smtp._tls.example.com
```

and begins:

```text
v=TLSRPTv1;
```

## Why They Matter

SPF, DKIM, and DMARC focus primarily on sender identity and message authorization. MTA-STS and TLS-RPT address a different layer: the security and observability of SMTP transport between mail systems.

## Tool Scope

The audit currently checks whether the DNS discovery records exist. It does not fetch or validate the HTTPS MTA-STS policy file.
