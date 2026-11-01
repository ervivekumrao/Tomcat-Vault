/*
 * Copyright 2024-2026 the original author or authors (Vivek Umrao).
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

package umrao.tomcat.vault;

import umrao.tomcat.vault.audit.VaultAuditLogger;
import umrao.tomcat.vault.exception.DecryptionException;
import umrao.tomcat.vault.exception.SecretResolutionException;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

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
 * @author Vivek Umrao
 */
public class ReferencePropertyDecryptor {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(ReferencePropertyDecryptor.class);
    private static final Logger JUL_LOGGER = Logger.getLogger(ReferencePropertyDecryptor.class.getName());

    // Properties considered sensitive; values must NEVER be logged in cleartext
    private static final String[] SENSITIVE_PROPERTIES = {
            "password", "pwd", "pass", "username", "user", "url", "connectionproperties",
            "secret", "token", "apikey", "credential", "privatekey", "auth"
    };

    private final VaultCrypto crypto;

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
    @SuppressWarnings("SynchronizationOnLocalVariableOrMethodParameter")
    public void decryptProperties(Reference reference) {
        if (reference == null) {
            return;
        }

        synchronized (reference) {
            String resourceName = reference.getClassName() != null ? reference.getClassName() : "DataSource";
            String providerName = (crypto.getKeyProvider() != null)
                    ? crypto.getKeyProvider().getProviderName()
                    : "VaultCrypto";

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
                String current = rawValue;
                long startTime = System.currentTimeMillis();

                // 1. Resolve direct or embedded cloud secrets
                if (umrao.tomcat.vault.secret.SecretResolverRegistry.getInstance().isResolvable(current)) {
                    try {
                        current = umrao.tomcat.vault.secret.SecretResolverRegistry.getInstance().resolve(current);
                    } catch (Exception e) {
                        long duration = System.currentTimeMillis() - startTime;
                        VaultAuditLogger.getInstance().logEvent("SECRET_RESOLUTION_FAILED", resourceName, property, "SecretResolverRegistry", "FAILURE", duration);
                        LOGGER.error("Failed to resolve external secret for property [" + property + "]: " + e.getMessage(), e);
                        JUL_LOGGER.log(Level.SEVERE, "Failed to resolve external secret for property [" + property + "]: " + e.getMessage(), e);
                        throw new SecretResolutionException("External secret resolution failure for property '" + property + "'", e);
                    }
                } else if (umrao.tomcat.vault.secret.SecretResolverRegistry.getInstance().hasResolvable(current)) {
                    try {
                        current = umrao.tomcat.vault.secret.SecretResolverRegistry.getInstance().resolveEmbedded(current);
                    } catch (Exception e) {
                        long duration = System.currentTimeMillis() - startTime;
                        VaultAuditLogger.getInstance().logEvent("SECRET_RESOLUTION_FAILED", resourceName, property, "SecretResolverRegistry", "FAILURE", duration);
                        LOGGER.error("Failed to resolve external secret for property [" + property + "]: " + e.getMessage(), e);
                        JUL_LOGGER.log(Level.SEVERE, "Failed to resolve external secret for property [" + property + "]: " + e.getMessage(), e);
                        throw new SecretResolutionException("External secret resolution failure for property '" + property + "'", e);
                    }
                }

                // 2. Decrypt direct or embedded ENC(...) tokens
                if (crypto.isEncrypted(current)) {
                    try {
                        current = crypto.decrypt(current);
                    } catch (Exception e) {
                        long duration = System.currentTimeMillis() - startTime;
                        VaultAuditLogger.getInstance().logEvent("DECRYPTION_FAILED", resourceName, property, providerName, "FAILURE", duration);
                        LOGGER.error("Failed to decrypt DataSource property [" + property + "]: " + e.getMessage(), e);
                        JUL_LOGGER.log(Level.SEVERE, "Failed to decrypt DataSource property [" + property + "]: " + e.getMessage(), e);
                        throw new DecryptionException("Decryption failure for property '" + property + "'", e);
                    }
                } else if (crypto.hasEmbeddedEncrypted(current)) {
                    try {
                        current = crypto.decryptEmbedded(current);
                    } catch (Exception e) {
                        long duration = System.currentTimeMillis() - startTime;
                        VaultAuditLogger.getInstance().logEvent("DECRYPTION_FAILED", resourceName, property, providerName, "FAILURE", duration);
                        LOGGER.error("Failed to decrypt DataSource property [" + property + "]: " + e.getMessage(), e);
                        JUL_LOGGER.log(Level.SEVERE, "Failed to decrypt DataSource property [" + property + "]: " + e.getMessage(), e);
                        throw new DecryptionException("Decryption failure for property '" + property + "'", e);
                    }
                }

                if (current != null && !current.equals(rawValue)) {
                    long duration = System.currentTimeMillis() - startTime;
                    reference.remove(i);
                    reference.add(i, new StringRefAddr(property, current));
                    decryptedCount++;

                    VaultAuditLogger.getInstance().logEvent("CREDENTIAL_DECRYPTED", resourceName, property, providerName, "SUCCESS", duration);

                    if (LOGGER.isDebugEnabled() || JUL_LOGGER.isLoggable(Level.FINE)) {
                        LOGGER.debug("Successfully decrypted DataSource property: " + property);
                        JUL_LOGGER.log(Level.FINE, "Successfully decrypted DataSource property: {0}", property);
                    }
                }
            }

            if (LOGGER.isInfoEnabled() || JUL_LOGGER.isLoggable(Level.INFO)) {
                LOGGER.info("Tomcat Vault processed " + originalList.size() + " DataSource properties (" + decryptedCount + " decrypted).");
                JUL_LOGGER.log(Level.INFO, "Tomcat Vault processed {0} DataSource properties ({1} decrypted).",
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
