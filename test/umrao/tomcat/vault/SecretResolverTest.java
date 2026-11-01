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

import umrao.tomcat.vault.secret.SecretResolver;
import umrao.tomcat.vault.secret.SecretResolverRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.naming.Reference;
import javax.naming.StringRefAddr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class SecretResolverTest {

    @AfterEach
    void tearDown() {
        System.clearProperty("aws.secret.prod.db.password");
        System.clearProperty("vault.secret.database.creds.password");
        SecretResolverRegistry.getInstance().resetDefaultResolvers();
    }

    @Test
    @DisplayName("SecretResolverRegistry resolves expressions using system properties")
    void testStandardCloudSecretResolver() {
        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();

        assertTrue(registry.isResolvable("AWS_SECRET(prod/db#password)"));
        assertTrue(registry.isResolvable("VAULT(secret/database/creds#password)"));
        assertTrue(registry.isResolvable("AZURE_VAULT(my-secret)"));
        assertTrue(registry.isResolvable("GCP_SECRET(my-gcp-secret)"));
        assertFalse(registry.isResolvable("PLAIN_PASSWORD"));
        assertFalse(registry.isResolvable(null));
        assertFalse(registry.isResolvable(""));

        System.setProperty("aws.secret.prod.db.password", "ResolvedAwsSecret123");
        String resolvedAws = registry.resolve("AWS_SECRET(prod/db#password)");
        assertEquals("ResolvedAwsSecret123", resolvedAws);

        System.setProperty("vault.secret.database.creds.password", "ResolvedVaultSecret456");
        String resolvedVault = registry.resolve("VAULT(secret/database/creds#password)");
        assertEquals("ResolvedVaultSecret456", resolvedVault);

        // Unresolved returns original expression unchanged
        assertEquals("AZURE_VAULT(unknown-secret)", registry.resolve("AZURE_VAULT(unknown-secret)"));
    }

    @Test
    @DisplayName("SecretResolverRegistry custom resolver registration and lifecycle")
    void testCustomResolver() {
        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();

        SecretResolver customResolver = new SecretResolver() {
            @Override
            public boolean supports(String expression) {
                return expression != null && expression.startsWith("CUSTOM_VAULT(");
            }

            @Override
            public String resolve(String expression) {
                return "CustomVaultResolvedValue";
            }

            @Override
            public String getResolverName() {
                return "MockCustomResolver";
            }
        };

        registry.registerResolver(customResolver);
        assertTrue(registry.isResolvable("CUSTOM_VAULT(test)"));
        assertEquals("CustomVaultResolvedValue", registry.resolve("CUSTOM_VAULT(test)"));
        assertEquals("MockCustomResolver", customResolver.getResolverName());

        registry.unregisterResolver(customResolver);
        assertFalse(registry.isResolvable("CUSTOM_VAULT(test)"));
    }

    @Test
    @DisplayName("ReferencePropertyDecryptor resolves cloud secret expressions directly in JNDI Reference")
    void testReferenceDecryptorWithCloudSecret() {
        System.setProperty("aws.secret.prod.db.password", "CloudInjectedSecretPassword");

        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("password", "AWS_SECRET(prod/db#password)"));
        ref.add(new StringRefAddr("username", "appuser"));

        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        decryptor.decryptProperties(ref);

        assertEquals("CloudInjectedSecretPassword", ref.get("password").getContent().toString());
        assertEquals("appuser", ref.get("username").getContent().toString());
    }

    @Test
    @DisplayName("Strict mode: SecretResolverRegistry rejects unresolved cloud secrets")
    void testStrictModeInSecretResolverRegistry() {
        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        try {
            SecretResolverRegistry registry = SecretResolverRegistry.getInstance();
            assertThrows(umrao.tomcat.vault.exception.SecretResolutionException.class,
                    () -> registry.resolve("AWS_SECRET(nonexistent-secret#field)"));
        } finally {
            System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        }
    }
}

