/*
 * acme4j - Java ACME client
 *
 * Copyright (C) 2026 Richard "Shred" Körber
 *   http://acme4j.shredzone.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */
package org.shredzone.acme4j.connector;

import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Keeps the current nonce for a request. Make sure that the {@link #close()} method is
 * always invoked, otherwise the related {@link org.shredzone.acme4j.Session} will be
 * blocked.
 * <p>
 * This object is for internal use only.
 *
 * @since 4.0.0
 */
public interface NonceHolder extends AutoCloseable {
    /**
     * Gets the last base64 encoded nonce, or {@code null} if the session is new.
     */
    @Nullable
    String getNonce();

    /**
     * Sets the base64 encoded nonce received by the server.
     */
    void setNonce(@Nullable String nonce);

    /**
     * Closes the NonceHolder. Must be invoked!
     */
    void close();
}
