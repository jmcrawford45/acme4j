# dns-persist-01 Challenge

With the `dns-persist-01` challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a persistent TXT record that contains CA and account identification information.

This challenge is specified in [draft-ietf-acme-dns-persist](https://datatracker.ietf.org/doc/draft-ietf-acme-dns-persist/).

!!! warning
    The support of this challenge is **experimental**. The implementation is only unit tested for compliance with the specification, but is not integration tested yet. There may be breaking changes in this part of the API in future releases.

Unlike transient challenges like `dns-01`, the `dns-persist-01` challenge requires a persistent DNS TXT record that remains in place across multiple certificate validations. This is particularly useful for IoT deployments, multi-tenant platforms, and batch certificate operations where traditional challenge methods are impractical.

`DnsPersist01Challenge` provides methods to construct the required TXT record:

```java
DnsPersist01Challenge challenge = auth.findChallenge(DnsPersist01Challenge.class);

// Get the resource record name where the TXT record should be placed
String resourceRecordName = challenge.getRRName(auth.getIdentifier());

// Get the list of issuer domain names provided by the CA
List<String> issuerDomainNames = challenge.getIssuerDomainNames();

// Select one issuer domain name (e.g., the first one)
String issuerDomainName = issuerDomainNames.get(0);

// Build the TXT record value
String recordValue = challenge.buildRecordValue(issuerDomainName);
```

The CA expects a TXT record at `resourceRecordName` (e.g., `_validation-persist.example.org.`) with the constructed record value. The `getRRName()` method converts the domain name to a resource record name (including the trailing full stop).

The record value follows the RFC 8659 issue-value syntax and contains:
- The issuer domain name (selected from the CA-provided list)
- The account URI parameter (`accounturi=...`)
- Optional policy parameter (e.g., `policy=wildcard`)
- Optional expiration timestamp (`persistUntil=...`)

Example with additional parameters:

```java
// Build record value with wildcard policy and expiration timestamp
String recordValue = challenge.buildRecordValue(
    issuerDomainName,
    "wildcard",           // policy parameter
    1735689600L          // persistUntil (UNIX timestamp in seconds)
);
```

The validation is successful if the CA finds the TXT record at the expected location with the correct issuer domain name and account URI. The record can remain in place for future validations, making it suitable for long-term automated certificate management.
