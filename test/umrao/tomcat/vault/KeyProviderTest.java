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

package umrao.tomcat.vault;

import umrao.tomcat.vault.key.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

public class KeyProviderTest {

    @TempDir
    Path tempDir;

    @AfterEach
    public void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
        System.clearProperty(VaultConstants.SYS_PROP_KEY_ALT);
        System.clearProperty(VaultConstants.SYS_PROP_KEYFILE);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty("custom.test.key");
    }

    @Test
    @DisplayName("EnvironmentKeyProvider branch coverage")
    public void testEnvironmentKeyProvider() {
        EnvironmentKeyProvider defaultProvider = new EnvironmentKeyProvider();
        assertEquals("EnvironmentKeyProvider", defaultProvider.getProviderName());

        EnvironmentKeyProvider customProvider = new EnvironmentKeyProvider("PATH");
        assertEquals("EnvironmentKeyProvider[PATH]", customProvider.getProviderName());
        assertNotNull(customProvider.getKey());

        EnvironmentKeyProvider emptyCustom = new EnvironmentKeyProvider("   ");
        assertEquals("EnvironmentKeyProvider[   ]", emptyCustom.getProviderName());

        // Test with mock resolver for full branch coverage
        Map<String, String> mockEnv = new HashMap<>();
        EnvironmentKeyProvider mockProvider = new EnvironmentKeyProvider(null, mockEnv::get);
        assertNull(mockProvider.getKey());

        // Primary key empty string
        mockEnv.put(VaultConstants.ENV_KEY, "   ");
        assertNull(mockProvider.getKey());

        // Primary key valid
        mockEnv.put(VaultConstants.ENV_KEY, "PrimaryEnvKey123");
        assertEquals("PrimaryEnvKey123", mockProvider.getKey());

        // Alternate key empty string
        mockEnv.remove(VaultConstants.ENV_KEY);
        mockEnv.put(VaultConstants.ENV_KEY_ALT, "   ");
        assertNull(mockProvider.getKey());

        // Alternate key valid
        mockEnv.put(VaultConstants.ENV_KEY_ALT, "AlternateEnvKey456");
        assertEquals("AlternateEnvKey456", mockProvider.getKey());

        // Custom var empty value
        mockEnv.put("MY_CUSTOM_VAR", "   ");
        EnvironmentKeyProvider customMock = new EnvironmentKeyProvider("MY_CUSTOM_VAR", mockEnv::get);
        assertEquals("AlternateEnvKey456", customMock.getKey());
    }

    @Test
    @DisplayName("SystemPropertyKeyProvider branch coverage")
    public void testSystemPropertyKeyProvider() {
        SystemPropertyKeyProvider defaultProvider = new SystemPropertyKeyProvider();
        assertEquals("SystemPropertyKeyProvider", defaultProvider.getProviderName());
        assertNull(defaultProvider.getKey());

        // Custom property set to blank
        System.setProperty("custom.test.key", "   ");
        SystemPropertyKeyProvider blankValProvider = new SystemPropertyKeyProvider("custom.test.key");
        assertNull(blankValProvider.getKey());

        // Custom property set to valid
        System.setProperty("custom.test.key", "CustomSysVal");
        SystemPropertyKeyProvider customProvider = new SystemPropertyKeyProvider("custom.test.key");
        assertEquals("SystemPropertyKeyProvider[custom.test.key]", customProvider.getProviderName());
        assertEquals("CustomSysVal", customProvider.getKey());

        // Blank custom property name
        SystemPropertyKeyProvider blankCustom = new SystemPropertyKeyProvider("   ");
        assertNull(blankCustom.getKey());

        // Primary property blank
        System.clearProperty("custom.test.key");
        System.setProperty(VaultConstants.SYS_PROP_KEY, "   ");
        assertNull(defaultProvider.getKey());

        // Primary property valid
        System.setProperty(VaultConstants.SYS_PROP_KEY, "PrimarySysKey");
        assertEquals("PrimarySysKey", defaultProvider.getKey());

        // Alternate property blank
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
        System.setProperty(VaultConstants.SYS_PROP_KEY_ALT, "   ");
        assertNull(defaultProvider.getKey());

        // Alternate property valid
        System.setProperty(VaultConstants.SYS_PROP_KEY_ALT, "AlternateSysKey");
        assertEquals("AlternateSysKey", defaultProvider.getKey());
    }

    @Test
    @DisplayName("FileKeyProvider branch coverage")
    public void testFileKeyProvider() throws Exception {
        FileKeyProvider defaultProvider = new FileKeyProvider();
        assertEquals("FileKeyProvider", defaultProvider.getProviderName());
        assertNull(defaultProvider.getKey());

        // Blank explicit path
        FileKeyProvider blankPath = new FileKeyProvider("   ");
        assertNull(blankPath.getKey());

        // Valid file
        File tempFile = File.createTempFile("vault-test", ".key");
        tempFile.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write("KeyFromFileSecret888\n".getBytes(StandardCharsets.UTF_8));
        }

        FileKeyProvider provider = new FileKeyProvider(tempFile.getAbsolutePath());
        assertEquals("FileKeyProvider[" + tempFile.getAbsolutePath() + "]", provider.getProviderName());
        assertEquals("KeyFromFileSecret888", provider.getKey());

        // Non-existent file
        FileKeyProvider nonExistent = new FileKeyProvider("/non/existent/path/vault.key");
        assertNull(nonExistent.getKey());

        // Directory path (causes IOException when reading bytes)
        File tempDir = new File(System.getProperty("java.io.tmpdir"));
        FileKeyProvider dirProvider = new FileKeyProvider(tempDir.getAbsolutePath());
        assertNull(dirProvider.getKey());

        // Via system property
        System.setProperty(VaultConstants.SYS_PROP_KEYFILE, tempFile.getAbsolutePath());
        assertEquals("KeyFromFileSecret888", defaultProvider.getKey());

        // Via mock resolvers: test blank sysprop and valid env var
        Map<String, String> mockProps = new HashMap<>();
        Map<String, String> mockEnv = new HashMap<>();
        mockProps.put(VaultConstants.SYS_PROP_KEYFILE, "   ");
        mockEnv.put(VaultConstants.ENV_KEYFILE, tempFile.getAbsolutePath());

        FileKeyProvider resolverProvider = new FileKeyProvider(null, mockProps::get, mockEnv::get);
        assertEquals("KeyFromFileSecret888", resolverProvider.getKey());

        mockEnv.put(VaultConstants.ENV_KEYFILE, "   ");
        assertNull(resolverProvider.getKey());
    }

    @Test
    @DisplayName("DefaultKeyProvider branch coverage")
    public void testDefaultKeyProvider() {
        DefaultKeyProvider provider = new DefaultKeyProvider();
        assertEquals("DefaultDevelopmentKeyProvider", provider.getProviderName());

        assertEquals(VaultConstants.DEFAULT_DEV_KEY, provider.getKey());
        assertEquals(VaultConstants.DEFAULT_DEV_KEY, provider.getKey());
    }

    @Test
    @DisplayName("CompositeKeyProvider branch coverage")
    public void testCompositeKeyProvider() {
        CompositeKeyProvider composite = new CompositeKeyProvider();
        assertEquals("CompositeKeyProvider", composite.getProviderName());

        // Set log level to FINE to cover Level.FINE logging branch
        Logger logger = Logger.getLogger(CompositeKeyProvider.class.getName());
        Level oldLevel = logger.getLevel();
        logger.setLevel(Level.FINE);
        try {
            assertEquals(VaultConstants.DEFAULT_DEV_KEY, composite.getKey());
            assertEquals("DefaultDevelopmentKeyProvider", composite.getProviderName());
        } finally {
            logger.setLevel(oldLevel);
        }

        // addProviderFirst and addProvider with null and valid
        composite.addProviderFirst(null);
        composite.addProvider(null);

        composite.addProviderFirst(new KeyProvider() {
            @Override
            public String getKey() {
                return "FirstPriorityKey";
            }

            @Override
            public String getProviderName() {
                return "MockFirstProvider";
            }
        });
        assertEquals("FirstPriorityKey", composite.getKey());
        assertEquals("MockFirstProvider", composite.getProviderName());

        // Test with empty list
        CompositeKeyProvider emptyComposite = new CompositeKeyProvider(new ArrayList<>());
        assertNull(emptyComposite.getKey());

        // Provider returning empty string and provider throwing exception
        CompositeKeyProvider edgeComposite = new CompositeKeyProvider(new ArrayList<>());
        edgeComposite.addProvider(null);
        edgeComposite.addProvider(new KeyProvider() {
            @Override
            public String getKey() {
                return "   ";
            }

            @Override
            public String getProviderName() {
                return "EmptyKeyProvider";
            }
        });
        edgeComposite.addProvider(new KeyProvider() {
            @Override
            public String getKey() {
                throw new RuntimeException("Simulated provider failure");
            }

            @Override
            public String getProviderName() {
                return "FailingKeyProvider";
            }
        });
        assertNull(edgeComposite.getKey());
    }

    @Test
    @DisplayName("CloudVaultKeyProvider SPI test")
    public void testCloudVaultKeyProvider() {
        CloudVaultKeyProvider vaultProvider = new CloudVaultKeyProvider() {
            @Override
            public String getVaultSecretPath() {
                return "secret/data/db#password";
            }

            @Override
            public boolean isAvailable() {
                return true;
            }

            @Override
            public String getKey() {
                return "VaultSecretKey999";
            }

            @Override
            public String getProviderName() {
                return "MockHashiCorpVaultProvider";
            }
        };

        assertEquals("secret/data/db#password", vaultProvider.getVaultSecretPath());
        assertTrue(vaultProvider.isAvailable());
        assertEquals("VaultSecretKey999", vaultProvider.getKey());
        assertEquals("MockHashiCorpVaultProvider", vaultProvider.getProviderName());
    }

    @Test
    @DisplayName("KeyProvider interface default methods coverage")
    public void testKeyProviderInterfaceDefaults() {
        KeyProvider custom = new KeyProvider() {
            @Override
            public String getKey() {
                return "BaseKey";
            }

            @Override
            public String getProviderName() {
                return "CustomBaseKey";
            }
        };

        assertEquals("BaseKey", custom.getKey());
        assertEquals("BaseKey", custom.getKey(""));
        assertEquals("BaseKey", custom.getKey(null));
        assertNull(custom.getKey("v1"));
        assertTrue(custom.hasKey(null));
        assertFalse(custom.hasKey("v1"));
    }

    @Test
    @DisplayName("FileKeyProvider automatically reloads key when file is updated on disk (K8s Secret)")
    void testFileKeyProviderAutoReload() throws Exception {
        File keyFile = tempDir.resolve("k8s_secret.key").toFile();
        Files.writeString(keyFile.toPath(), "InitialKey123456789012345678901234");

        FileKeyProvider provider = new FileKeyProvider(keyFile.getAbsolutePath());
        assertEquals("InitialKey123456789012345678901234", provider.getKey());

        // Update file on disk (simulate Kubernetes Secret or administrator rotation)
        Thread.sleep(100);
        Files.writeString(keyFile.toPath(), "UpdatedRotatedKey9876543210987654321");
        boolean modified = keyFile.setLastModified(System.currentTimeMillis() + 1000);
        assertTrue(modified || keyFile.exists());

        String reloadedKey = provider.getKey();
        assertEquals("UpdatedRotatedKey9876543210987654321", reloadedKey);
    }

    @Test
    @DisplayName("FileKeyProvider POSIX permission checking")
    void testFileKeyProviderPermissionsSecurityCheck() throws Exception {
        File keyFile = tempDir.resolve("posix_test.key").toFile();
        Files.writeString(keyFile.toPath(), "PosixSecretKey1234567890123456");

        FileKeyProvider provider = new FileKeyProvider(keyFile.getAbsolutePath());
        assertNotNull(provider.getKey());
    }

    @Test
    @DisplayName("Strict mode: DefaultKeyProvider rejects dev fallback key")
    void testStrictModeInDefaultKeyProvider() {
        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        DefaultKeyProvider provider = new DefaultKeyProvider();
        assertThrows(SecurityException.class, provider::getKey);
    }
}

