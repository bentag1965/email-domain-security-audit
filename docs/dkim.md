# DKIM

DKIM uses cryptographic signatures so receiving systems can verify that message content was authorized by a signing domain.

Records are stored beneath a selector:

```text
selector._domainkey.example.com
```

Selectors are chosen by the sending platform, so there is no universal query that reveals every possible selector. This tool checks candidate selectors supplied by the user and treats missing candidates as inconclusive rather than proof that DKIM is absent.
