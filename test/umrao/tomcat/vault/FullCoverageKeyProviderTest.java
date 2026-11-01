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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import umrao.tomcat.vault.key.CompositeKeyProvider;
import umrao.tomcat.vault.key.DefaultKeyProvider;
import umrao.tomcat.vault.key.EnvironmentKeyProvider;
import umrao.tomcat.vault.key.FileKeyProvider;
import umrao.tomcat.vault.key.KeyProvider;
import umrao.tomcat.vault.key.KeyStoreKeyProvider;
import umrao.tomcat.vault.key.SystemPropertyKeyProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class FullCoverageKeyProviderTest {

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE_TYPE);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE_ALIAS);
        System.clearProperty(VaultConstants.SYS_PROP_KEYFILE);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
    }

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE_PASSWORD);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE_TYPE);
        System.clearProperty(VaultConstants.SYS_PROP_KEYSTORE_ALIAS);
        System.clearProperty(VaultConstants.SYS_PROP_KEYFILE);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
    }

    @Test
    void testDefaultKeyProviderStrict() {
        DefaultKeyProvider provider = new DefaultKeyProvider();
        assertEquals("DefaultDevelopmentKeyProvider", provider.getProviderName());
        assertEquals(VaultConstants.DEFAULT_DEV_KEY, provider.getKey());

        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        assertThrows(SecurityException.class, provider::getKey);
    }

    @Test
    void testSystemPropertyKeyProviderBranches() {
        SystemPropertyKeyProvider provider = new SystemPropertyKeyProvider("custom.vault.key");
        assertNull(provider.getKey());

        System.setProperty("custom.vault.key", "my-custom-key");
        assertEquals("my-custom-key", provider.getKey());

        // Alias resolution: null or empty returns getKey()
        assertEquals("my-custom-key", provider.getKey(null));
        assertEquals("my-custom-key", provider.getKey(""));

        // Custom property with alias
        System.setProperty("custom.vault.key.v2", "v2-secret-key");
        assertEquals("v2-secret-key", provider.getKey("v2"));

        // Default property with alias
        System.clearProperty("custom.vault.key.v2");
        System.setProperty("tomcat.vault.key.v3", "v3-secret-key");
        SystemPropertyKeyProvider defaultProvider = new SystemPropertyKeyProvider();
        assertEquals("v3-secret-key", defaultProvider.getKey("v3"));

        // Alt versioned key tomcat.encryption.key.v4
        System.setProperty(VaultConstants.SYS_PROP_KEY_ALT + ".v4", "v4-secret-key");
        assertEquals("v4-secret-key", defaultProvider.getKey("v4"));
    }

    @Test
    void testEnvironmentKeyProviderBranches() {
        Map<String, String> mockEnv = new HashMap<>();
        mockEnv.put("MY_VAULT_KEY", "env-secret-123");
        mockEnv.put("MY_VAULT_KEY_V2", "env-v2-key");
        mockEnv.put("TOMCAT_VAULT_KEY_V3", "env-v3-key");
        mockEnv.put("TOMCAT_ENCRYPTION_KEY_V4", "env-v4-key");

        EnvironmentKeyProvider provider = new EnvironmentKeyProvider("MY_VAULT_KEY", mockEnv::get);
        assertEquals("EnvironmentKeyProvider[MY_VAULT_KEY]", provider.getProviderName());
        assertEquals("env-secret-123", provider.getKey());

        // null and empty alias returns default key
        assertEquals("env-secret-123", provider.getKey(null));
        assertEquals("env-secret-123", provider.getKey("   "));

        // Custom env with alias
        assertEquals("env-v2-key", provider.getKey("v2"));

        // Standard env with alias
        EnvironmentKeyProvider defaultProvider = new EnvironmentKeyProvider(null, mockEnv::get);
        assertEquals("env-v3-key", defaultProvider.getKey("v3"));
        assertEquals("env-v4-key", defaultProvider.getKey("v4"));

        // Resolver null fallback to System::getenv
        EnvironmentKeyProvider fallbackProvider = new EnvironmentKeyProvider("NON_EXISTENT_VAR", null);
        assertNull(fallbackProvider.getKey());
    }

    @Test
    void testCompositeKeyProviderBranches() {
        // Constructor with null
        CompositeKeyProvider composite = new CompositeKeyProvider(null);
        assertEquals("CompositeKeyProvider", composite.getProviderName());
        assertNotNull(composite.getKey());
        assertEquals("DefaultDevelopmentKeyProvider", composite.getProviderName());

        // Add provider and null provider in list
        KeyProvider nullProvider = null;
        composite.addProvider(nullProvider);

        // Alias null or empty returns getKey()
        String defaultKey = composite.getKey();
        assertEquals(defaultKey, composite.getKey(null));
        assertEquals(defaultKey, composite.getKey("  "));

        // Register alias key directly
        composite.registerKey("v1", "v1-secret");
        assertEquals("v1-secret", composite.getKey("v1"));

        // Test with provider throwing SecurityException
        KeyProvider strictProvider = new KeyProvider() {
            @Override public String getKey() { throw new SecurityException("Strict mode rejection"); }
            @Override public String getKey(String alias) { throw new SecurityException("Strict mode alias rejection"); }
            @Override public String getProviderName() { return "StrictProvider"; }
        };
        CompositeKeyProvider strictComposite = new CompositeKeyProvider(Collections.singletonList(strictProvider));
        assertThrows(SecurityException.class, strictComposite::getKey);
        assertThrows(SecurityException.class, () -> strictComposite.getKey("someAlias"));

        // Test with provider throwing regular Exception (should continue to next provider)
        KeyProvider failingProvider = new KeyProvider() {
            @Override public String getKey() { throw new RuntimeException("Error"); }
            @Override public String getKey(String alias) { throw new RuntimeException("Error"); }
            @Override public String getProviderName() { return "FailingProvider"; }
        };
        KeyProvider goodProvider = new KeyProvider() {
            @Override public String getKey() { return "good-key"; }
            @Override public String getKey(String alias) { return "good-alias-" + alias; }
            @Override public String getProviderName() { return "GoodProvider"; }
        };

        CompositeKeyProvider fallbackComposite = new CompositeKeyProvider(Arrays.asList(failingProvider, goodProvider));
        assertEquals("good-key", fallbackComposite.getKey());
        assertEquals("good-alias-v2", fallbackComposite.getKey("v2"));

        // Unresolvable alias
        KeyProvider emptyProvider = new KeyProvider() {
            @Override public String getKey() { return null; }
            @Override public String getKey(String alias) { return null; }
            @Override public String getProviderName() { return "EmptyProvider"; }
        };
        CompositeKeyProvider emptyComposite = new CompositeKeyProvider(Collections.singletonList(emptyProvider));
        assertNull(emptyComposite.getKey("unresolvable"));
    }

    @Test
    void testFileKeyProviderBranches() throws Exception {
        // File does not exist
        File nonExistent = new File(tempDir.toFile(), "non-existent.key");
        FileKeyProvider provider = new FileKeyProvider(nonExistent.getAbsolutePath());
        assertNull(provider.getKey());

        // File exists and is valid
        File validFile = new File(tempDir.toFile(), "valid.key");
        Files.writeString(validFile.toPath(), "secret-file-key-123\n");
        FileKeyProvider validProvider = new FileKeyProvider(validFile.getAbsolutePath());
        assertEquals("secret-file-key-123", validProvider.getKey());

        // Second call hits cache (timestamp & size unchanged)
        assertEquals("secret-file-key-123", validProvider.getKey());

        // Test getKey(alias)
        assertEquals("secret-file-key-123", validProvider.getKey(null));
        assertEquals("secret-file-key-123", validProvider.getKey("   "));

        // Alias resolution via sibling file: valid.key.v2
        File aliasFile = new File(tempDir.toFile(), "valid.key.v2");
        Files.writeString(aliasFile.toPath(), "alias-v2-key");
        assertEquals("alias-v2-key", validProvider.getKey("v2"));

        // Alias resolution via sysprop
        File sysPropAliasFile = new File(tempDir.toFile(), "sysprop-alias.key");
        Files.writeString(sysPropAliasFile.toPath(), "sysprop-alias-key");
        Map<String, String> sysProps = new HashMap<>();
        sysProps.put("tomcat.vault.keyfile.v3", sysPropAliasFile.getAbsolutePath());
        FileKeyProvider propProvider = new FileKeyProvider(validFile.getAbsolutePath(), sysProps::get, k -> null);
        assertEquals("sysprop-alias-key", propProvider.getKey("v3"));

        // Alias resolution via env
        File envAliasFile = new File(tempDir.toFile(), "env-alias.key");
        Files.writeString(envAliasFile.toPath(), "env-alias-key");
        FileKeyProvider envProvider = new FileKeyProvider(validFile.getAbsolutePath(), k -> null, k -> "TOMCAT_VAULT_KEYFILE_V4".equals(k) ? envAliasFile.getAbsolutePath() : null);
        assertEquals("env-alias-key", envProvider.getKey("v4"));

        // When path is null
        FileKeyProvider nullPathProvider = new FileKeyProvider(null, k -> null, k -> null);
        assertNull(nullPathProvider.getKey());
        assertNull(nullPathProvider.getKey("anyAlias"));

        // Posix permission checks
        if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            File posixFile = new File(tempDir.toFile(), "insecure.key");
            Files.writeString(posixFile.toPath(), "posix-key");
            // Set 0777 permissions
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rwxrwxrwx");
            Files.setPosixFilePermissions(posixFile.toPath(), perms);

            // In non-strict mode, it warns and still returns key
            System.clearProperty(VaultConstants.SYS_PROP_STRICT);
            FileKeyProvider insecureProvider = new FileKeyProvider(posixFile.getAbsolutePath(), k -> null, k -> null);
            assertEquals("posix-key", insecureProvider.getKey());

            // In strict mode, it throws SecurityException
            System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
            assertThrows(SecurityException.class, insecureProvider::getKey);
            System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        }
    }

    @Test
    void testKeyStoreKeyProviderBranches() throws Exception {
        // Keystore does not exist
        KeyStoreKeyProvider missingProvider = new KeyStoreKeyProvider(
                tempDir.resolve("missing.p12").toString(),
                "password".toCharArray(),
                "myalias",
                "PKCS12"
        );
        assertNull(missingProvider.getKey());

        // Create valid PKCS12 keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey secretKey = kg.generateKey();

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection("secretPass".toCharArray());
        ks.setEntry("vaultkey", skEntry, protParam);

        File ksFile = tempDir.resolve("test-keystore.p12").toFile();
        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            ks.store(fos, "secretPass".toCharArray());
        }

        // Successfully load key
        KeyStoreKeyProvider validProvider = new KeyStoreKeyProvider(
                ksFile.getAbsolutePath(),
                "secretPass".toCharArray(),
                "vaultkey",
                "PKCS12"
        );
        assertNotNull(validProvider.getKey());
        assertTrue(validProvider.getProviderName().contains(ksFile.getAbsolutePath()));

        // Cache hit test
        assertNotNull(validProvider.getKey());

        // Null / missing alias in keystore
        assertNull(validProvider.getKey("non-existent-alias"));

        // Keystore with system properties and environment resolvers
        Map<String, String> sysProps = new HashMap<>();
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE, ksFile.getAbsolutePath());
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE_PASSWORD, "secretPass");
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE_TYPE, "PKCS12");
        sysProps.put(VaultConstants.SYS_PROP_KEYSTORE_ALIAS, "vaultkey");

        KeyStoreKeyProvider propProvider = new KeyStoreKeyProvider(null, null, null, null, sysProps::get, k -> null);
        assertNotNull(propProvider.getKey());

        // Keystore with environment variable resolvers
        Map<String, String> envVars = new HashMap<>();
        envVars.put(VaultConstants.ENV_KEYSTORE, ksFile.getAbsolutePath());
        envVars.put(VaultConstants.ENV_KEYSTORE_PASSWORD, "secretPass");
        envVars.put(VaultConstants.ENV_KEYSTORE_ALIAS, "vaultkey");

        KeyStoreKeyProvider envProvider = new KeyStoreKeyProvider(null, null, null, null, k -> null, envVars::get);
        assertNotNull(envProvider.getKey());

        // Keystore with corrupted file
        File corruptedFile = tempDir.resolve("corrupted.p12").toFile();
        Files.write(corruptedFile.toPath(), "NOT_A_VALID_KEYSTORE".getBytes());
        KeyStoreKeyProvider corruptProvider = new KeyStoreKeyProvider(
                corruptedFile.getAbsolutePath(),
                "secretPass".toCharArray(),
                "vaultkey",
                "PKCS12"
        );
        assertNull(corruptProvider.getKey());
    }

    @Test
    void testKeyStoreAndFileKeyProviderAdvancedEdgeCases() throws Exception {
        // 1. KeyStore with wrong password to trigger UnrecoverableKeyException
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        SecretKey mockKey = new javax.crypto.spec.SecretKeySpec("12345678901234567890123456789012".getBytes(), "AES");
        ks.setEntry("wrongPassKey", new KeyStore.SecretKeyEntry(mockKey), new KeyStore.PasswordProtection("pass1".toCharArray()));

        File ksFile = tempDir.resolve("advanced-ks.p12").toFile();
        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            ks.store(fos, "storepass".toCharArray());
        }

        // Wrong password when loading key triggers UnrecoverableKeyException (lines 154-156)
        KeyStoreKeyProvider wrongPassProvider = new KeyStoreKeyProvider(
                ksFile.getAbsolutePath(),
                "wrongKeyPass".toCharArray(),
                "wrongPassKey",
                "PKCS12"
        );
        assertNull(wrongPassProvider.getKey());

        // 2. FileKeyProvider directory instead of file triggers read failure
        File dirAsFile = tempDir.resolve("dirKey").toFile();
        assertTrue(dirAsFile.mkdirs() || dirAsFile.exists());
        FileKeyProvider dirProvider = new FileKeyProvider(dirAsFile.getAbsolutePath());
        assertNull(dirProvider.getKey());
    }
}
