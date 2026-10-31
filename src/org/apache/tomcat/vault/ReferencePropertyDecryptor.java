/*
 * Copyright 2024-2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.tomcat.vault;

import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Thread-safe interceptor for JNDI DataSource {@link Reference} objects.
 * Inspects connection pool properties (such as password, username, url) and decrypts
 * encrypted properties without exposing plaintext credentials in logs.
 * Compatible with all Apache Tomcat versions (Tomcat 7 through 11).
 */
public class ReferencePropertyDecryptor {

    private static final Logger LOGGER = Logger.getLogger(ReferencePropertyDecryptor.class.getName());

    // Properties considered sensitive; values must NEVER be logged in cleartext
    private static final String[] SENSITIVE_PROPERTIES = {
            "password", "pwd", "username", "user", "url", "connectionproperties"
    };

    private final VaultCrypto crypto;
    private final Object lock = new Object();

    public ReferencePropertyDecryptor() {
        this(new VaultCrypto());
    }

    public ReferencePropertyDecryptor(VaultCrypto crypto) {
        this.crypto = crypto != null ? crypto : new VaultCrypto();
    }

    /**
     * Inspects all RefAddr entries in the JNDI Reference, decrypts any encrypted values,
     * and safely updates the Reference in place without concurrent modification issues.
     *
     * @param reference the JNDI Reference describing the DataSource
     */
    public void decryptProperties(Reference reference) {
        if (reference == null) {
            return;
        }

        synchronized (lock) {
            // Snapshot current entries to avoid concurrent modification issues during iteration
            Enumeration<RefAddr> enumeration = reference.getAll();
            List<RefAddr> originalList = new ArrayList<>();
            while (enumeration.hasMoreElements()) {
                originalList.add(enumeration.nextElement());
            }

            int decryptedCount = 0;
            for (int i = 0; i < originalList.size(); i++) {
                RefAddr refAddr = originalList.get(i);
                if (refAddr == null) {
                    continue;
                }

                String property = refAddr.getType();
                Object content = refAddr.getContent();
                if (property == null || content == null) {
                    continue;
                }

                String rawValue = content.toString();
                String decryptedValue = null;

                if (org.apache.tomcat.vault.secret.SecretResolverRegistry.getInstance().isResolvable(rawValue)) {
                    try {
                        decryptedValue = org.apache.tomcat.vault.secret.SecretResolverRegistry.getInstance().resolve(rawValue);
                    } catch (Exception e) {
                        LOGGER.log(Level.SEVERE, "Failed to resolve external secret for property [" + property + "]: " + e.getMessage(), e);
                        throw new RuntimeException("External secret resolution failure for property '" + property + "'", e);
                    }
                } else if (crypto.isEncrypted(rawValue)) {
                    try {
                        decryptedValue = crypto.decrypt(rawValue);
                    } catch (Exception e) {
                        LOGGER.log(Level.SEVERE, "Failed to decrypt DataSource property [" + property + "]: " + e.getMessage(), e);
                        throw new RuntimeException("Decryption failure for property '" + property + "'", e);
                    }
                }

                if (decryptedValue != null && !decryptedValue.equals(rawValue)) {
                    reference.remove(i);
                    reference.add(i, new StringRefAddr(property, decryptedValue));
                    decryptedCount++;

                    if (LOGGER.isLoggable(Level.FINE)) {
                        LOGGER.log(Level.FINE, "Successfully decrypted DataSource property: {0}", property);
                    }
                }
            }

            if (LOGGER.isLoggable(Level.INFO)) {
                LOGGER.log(Level.INFO, "Tomcat Vault processed {0} DataSource properties ({1} decrypted).",
                        new Object[]{originalList.size(), decryptedCount});
            }
        }
    }

    /**
     * Checks if a configuration attribute name represents a sensitive credential.
     *
     * @param propertyName property key
     * @return true if sensitive
     */
    public static boolean isSensitive(String propertyName) {
        if (propertyName == null) return false;
        String lower = propertyName.toLowerCase();
        for (String s : SENSITIVE_PROPERTIES) {
            if (lower.contains(s)) {
                return true;
            }
        }
        return false;
    }
}
