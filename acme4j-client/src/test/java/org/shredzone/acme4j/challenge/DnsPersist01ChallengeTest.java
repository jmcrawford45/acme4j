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

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.shredzone.acme4j.toolbox.TestUtils.getJSON;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.Identifier;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.exception.AcmeProtocolException;
import org.shredzone.acme4j.toolbox.JSONBuilder;
import org.shredzone.acme4j.toolbox.TestUtils;

class DnsPersist01ChallengeTest {

    private final Login login = TestUtils.login();

    @Test
    public void testDnsPersistChallenge() {
        DnsPersist01Challenge challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));

        assertThat(challenge.getType()).isEqualTo(DnsPersist01Challenge.TYPE);
        assertThat(challenge.getStatus()).isEqualTo(Status.PENDING);

        assertThat(challenge.getRRName("www.example.org"))
                .isEqualTo("_validation-persist.www.example.org.");
        assertThat(challenge.getRRName(Identifier.dns("www.example.org")))
                .isEqualTo("_validation-persist.www.example.org.");
        assertThatExceptionOfType(AcmeProtocolException.class)
                .isThrownBy(() -> challenge.getRRName(Identifier.ip("127.0.0.10")));

        JSONBuilder response = new JSONBuilder();
        challenge.prepareResponse(response);

        assertThatJson(response.toString()).isEqualTo("{}");
    }

    @Test
    public void testIssuerDomainNames() {
        DnsPersist01Challenge challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));

        List<String> issuerDomainNames = challenge.getIssuerDomainNames();
        assertThat(issuerDomainNames).hasSize(2);
        assertThat(issuerDomainNames).containsExactly("ca.example.com", "authority.example.org");
    }

    @Test
    public void testAccountUri() {
        DnsPersist01Challenge challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));

        assertThat(challenge.getAccountUri()).isEqualTo("https://example.com/acme/account/1");
    }

    @Test
    public void testBuildRecordValue() {
        DnsPersist01Challenge challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));

        // Test basic record value
        String recordValue = challenge.buildRecordValue("ca.example.com");
        assertThat(recordValue).isEqualTo("ca.example.com; accounturi=https://example.com/acme/account/1");

        // Test with policy
        String recordValueWithPolicy = challenge.buildRecordValue("ca.example.com", "wildcard", null);
        assertThat(recordValueWithPolicy).isEqualTo("ca.example.com; accounturi=https://example.com/acme/account/1; policy=wildcard");

        // Test with persistUntil
        String recordValueWithPersist = challenge.buildRecordValue("ca.example.com", null, 1735689600L);
        assertThat(recordValueWithPersist).isEqualTo("ca.example.com; accounturi=https://example.com/acme/account/1; persistUntil=1735689600");

        // Test with all parameters
        String recordValueComplete = challenge.buildRecordValue("ca.example.com", "wildcard", 1735689600L);
        assertThat(recordValueComplete).isEqualTo("ca.example.com; accounturi=https://example.com/acme/account/1; policy=wildcard; persistUntil=1735689600");
    }

    @Test
    public void testDomainNameNormalization() {
        DnsPersist01Challenge challenge = new DnsPersist01Challenge(login, getJSON("dnsPersist01Challenge"));

        // Test with uppercase
        String recordValue = challenge.buildRecordValue("CA.EXAMPLE.COM");
        assertThat(recordValue).isEqualTo("ca.example.com; accounturi=https://example.com/acme/account/1");

        // Test with trailing dot
        String recordValueWithDot = challenge.buildRecordValue("ca.example.com.");
        assertThat(recordValueWithDot).isEqualTo("ca.example.com; accounturi=https://example.com/acme/account/1");
    }

}
