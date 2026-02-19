/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2025 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.challenge;

import static org.shredzone.acme4j.toolbox.AcmeUtils.toAce;

import java.io.Serial;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import edu.umd.cs.findbugs.annotations.Nullable;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.toolbox.JSON;

/**
 * Implements the {@value TYPE} challenge. It requires a persistent DNS record for domain
 * validation. See the acme4j documentation for a detailed explanation.
 *
 * @draft This class is currently based on an RFC draft. It may be changed or removed
 * without notice to reflect future changes to the draft. SemVer rules do not apply here.
 * @since 4.0.0
 */
public class DnsPersist01Challenge extends Challenge {
    @Serial
    private static final long serialVersionUID = 2716824024085136979L;

    /**
     * Challenge type name: {@value}
     */
    public static final String TYPE = "dns-persist-01";

    /**
     * The prefix of the domain name to be used for the DNS TXT record.
     */
    public static final String RECORD_NAME_PREFIX = "_validation-persist";

    private static final String KEY_ISSUER_DOMAIN_NAMES = "issuer-domain-names";

    /**
     * Creates a new generic {@link DnsPersist01Challenge} object.
     *
     * @param login
     *         {@link Login} the resource is bound with
     * @param data
     *         {@link JSON} challenge data
     */
    public DnsPersist01Challenge(Login login, JSON data) {
        super(login, data);
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param identifier
     *         Domain {@link Identifier} of the domain to be validated
     * @return Resource Record name (e.g. {@code _validation-persist.example.org.}, note
     * the trailing full stop character).
     */
    public String getRRName(Identifier identifier) {
        return getRRName(identifier.getDomain());
    }

    /**
     * Converts a domain identifier to the Resource Record name to be used for the DNS TXT
     * record.
     *
     * @param domain
     *         Domain name to be validated
     * @return Resource Record name (e.g. {@code _validation-persist.example.org.}, note
     * the trailing full stop character).
     */
    public String getRRName(String domain) {
        return RECORD_NAME_PREFIX + '.' + toAce(domain) + '.';
    }

    /**
     * Returns the list of issuer domain names provided by the CA. The client must select
     * one of these names to include in the TXT record.
     * <p>
     * All domain names are normalized to lowercase A-labels (ASCII encoding).
     *
     * @return Unmodifiable list of issuer domain names
     */
    public List<String> getIssuerDomainNames() {
        return getJSON().get(KEY_ISSUER_DOMAIN_NAMES)
                .map(value -> value.asArray().stream()
                        .map(element -> normalizeIssuerDomainName(element.asString()))
                        .toList())
                .orElse(Collections.emptyList());
    }

    /**
     * Returns the account URI to be used in the TXT record.
     *
     * @return Account URI as a string
     */
    public String getAccountUri() {
        return getLogin().getAccount().getLocation().toString();
    }

    /**
     * Builds a TXT record value for the persistent DNS validation.
     * <p>
     * The returned string follows the RFC 8659 issue-value syntax and contains the issuer
     * domain name and the accounturi parameter.
     * <p>
     * Note: This is a basic implementation. You may want to add additional parameters like
     * {@code policy=wildcard} or {@code persistUntil} as needed.
     *
     * @param issuerDomainName
     *         The issuer domain name to use (must be one from
     *         {@link #getIssuerDomainNames()})
     * @return TXT record value
     */
    public String buildRecordValue(String issuerDomainName) {
        return buildRecordValue(issuerDomainName, null, null);
    }

    /**
     * Builds a TXT record value for the persistent DNS validation.
     * <p>
     * The returned string follows the RFC 8659 issue-value syntax and contains the issuer
     * domain name, accounturi parameter, and optional policy and persistUntil parameters.
     *
     * @param issuerDomainName
     *         The issuer domain name to use (must be one from
     *         {@link #getIssuerDomainNames()})
     * @param policy
     *         Optional policy parameter (e.g., "wildcard"). Pass {@code null} to omit.
     * @param persistUntil
     *         Optional UNIX timestamp (in seconds) indicating when the record expires for
     *         new validations. Pass {@code null} to omit.
     * @return TXT record value
     */
    public String buildRecordValue(String issuerDomainName, @Nullable String policy, @Nullable Long persistUntil) {
        String normalized = normalizeIssuerDomainName(issuerDomainName);
        StringBuilder sb = new StringBuilder();
        sb.append(normalized);
        sb.append("; accounturi=").append(getAccountUri());

        if (policy != null && !policy.isEmpty()) {
            sb.append("; policy=").append(policy);
        }

        if (persistUntil != null) {
            sb.append("; persistUntil=").append(persistUntil);
        }

        return sb.toString();
    }

    /**
     * Normalizes an issuer domain name to lowercase A-label format as required by the
     * specification.
     *
     * @param issuerDomainName
     *         The issuer domain name to normalize
     * @return Normalized issuer domain name
     */
    private String normalizeIssuerDomainName(String issuerDomainName) {
        String normalized = toAce(issuerDomainName).toLowerCase(Locale.ENGLISH);
        // Remove trailing dot if present
        if (normalized.endsWith(".")) {
            return normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    @Override
    protected boolean acceptable(String type) {
        return TYPE.equals(type);
    }

}
