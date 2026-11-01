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

package umrao.tomcat.vault.key;

import umrao.tomcat.vault.VaultConstants;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * KeyProvider implementation that loads cryptographic keys from a Java KeyStore (PKCS#12 or JKS).
 * Supports Hardware Security Modules (HSM) and enterprise keystores compliant with FIPS 140-2 and PCI-DSS.
 * @author Vivek Umrao
 */
public class KeyStoreKeyProvider implements KeyProvider {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(KeyStoreKeyProvider.class);
    private static final String DEFAULT_ALIAS = "tomcat-vault";
    private static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

    private static final class KeystoreCacheEntry {
        final KeyStore keyStore;
        final long lastModified;
        final long lastFileSize;

        KeystoreCacheEntry(KeyStore keyStore, long lastModified, long lastFileSize) {
            this.keyStore = keyStore;
            this.lastModified = lastModified;
            this.lastFileSize = lastFileSize;
        }
    }

    private final Map<String, KeystoreCacheEntry> keystoreCache = new ConcurrentHashMap<>();
    private final Object reloadLock = new Object();

    private final String explicitPath;
    private final char[] explicitPassword;
    private final String explicitAlias;
    private final String explicitType;
    private final Function<String, String> sysPropResolver;
    private final Function<String, String> envResolver;

    public KeyStoreKeyProvider() {
        this(null, null, null, null, System::getProperty, System::getenv);
    }

    public KeyStoreKeyProvider(String path, char[] password, String alias, String type) {
        this(path, password, alias, type, System::getProperty, System::getenv);
    }

    public KeyStoreKeyProvider(String path, char[] password, String alias, String type,
                                Function<String, String> sysPropResolver,
                                Function<String, String> envResolver) {
        this.explicitPath = path;
        this.explicitPassword = password != null ? password.clone() : null;
        this.explicitAlias = alias;
        this.explicitType = type;
        this.sysPropResolver = sysPropResolver != null ? sysPropResolver : System::getProperty;
        this.envResolver = envResolver != null ? envResolver : System::getenv;
    }

    @Override
    public String getKey() {
        String defaultAlias = resolveAlias();
        return getKey(defaultAlias);
    }

    @Override
    public String getKey(String keyAlias) {
        String path = resolveKeystorePath();
        if (path == null) {
            return null;
        }

        File file = new File(path);
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            LOGGER.warn("KeyStore file configured but cannot be read: " + file.getAbsolutePath());
            return null;
        }

        char[] password = resolvePassword();
        String type = resolveKeystoreType();
        String targetAlias = (keyAlias != null && !keyAlias.trim().isEmpty()) ? keyAlias.trim() : resolveAlias();
        String absPath = file.getAbsolutePath();
        long currentModified = file.lastModified();
        long currentSize = file.length();

        KeyStore keyStore;
        KeystoreCacheEntry entry = keystoreCache.get(absPath);
        if (entry != null && currentModified == entry.lastModified && currentSize == entry.lastFileSize) {
            keyStore = entry.keyStore;
        } else {
            synchronized (reloadLock) {
                entry = keystoreCache.get(absPath);
                currentModified = file.lastModified();
                currentSize = file.length();
                if (entry != null && currentModified == entry.lastModified && currentSize == entry.lastFileSize) {
                    keyStore = entry.keyStore;
                } else {
                    try (InputStream is = Files.newInputStream(file.toPath())) {
                        KeyStore ks = KeyStore.getInstance(type);
                        ks.load(is, password);
                        keystoreCache.put(absPath, new KeystoreCacheEntry(ks, currentModified, currentSize));
                        keyStore = ks;
                    } catch (Exception e) {
                        LOGGER.error("Failed to load KeyStore [" + absPath + "]: " + e.getMessage(), e);
                        return null;
                    }
                }
            }
        }

        try {
            if (!keyStore.containsAlias(targetAlias)) {
                LOGGER.debug("KeyStore does not contain alias: " + targetAlias);
                return null;
            }

            Key key = keyStore.getKey(targetAlias, password);
            if (key == null) {
                return null;
            }

            byte[] encoded = key.getEncoded();
            if (encoded != null && encoded.length > 0) {
                String result = Base64.getEncoder().encodeToString(encoded);
                Arrays.fill(encoded, (byte) 0);
                return result;
            }
            return null;
        } catch (Exception e) {
            LOGGER.error("Failed to load key from KeyStore [" + absPath + "]: " + e.getMessage(), e);
            return null;
        } finally {
            if (password != null && password != explicitPassword) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private String resolveKeystorePath() {
        if (explicitPath != null && !explicitPath.trim().isEmpty()) {
            return explicitPath.trim();
        }
        String path = sysPropResolver.apply(VaultConstants.SYS_PROP_KEYSTORE);
        if (path != null && !path.trim().isEmpty()) {
            return path.trim();
        }
        path = envResolver.apply(VaultConstants.ENV_KEYSTORE);
        return (path != null && !path.trim().isEmpty()) ? path.trim() : null;
    }

    private char[] resolvePassword() {
        if (explicitPassword != null) {
            return explicitPassword;
        }
        String pass = sysPropResolver.apply(VaultConstants.SYS_PROP_KEYSTORE_PASSWORD);
        if (pass != null && !pass.isEmpty()) {
            return pass.toCharArray();
        }
        pass = envResolver.apply(VaultConstants.ENV_KEYSTORE_PASSWORD);
        if (pass != null && !pass.isEmpty()) {
            return pass.toCharArray();
        }
        return "".toCharArray();
    }

    private String resolveKeystoreType() {
        if (explicitType != null && !explicitType.trim().isEmpty()) {
            return explicitType.trim();
        }
        String t = sysPropResolver.apply(VaultConstants.SYS_PROP_KEYSTORE_TYPE);
        return (t != null && !t.trim().isEmpty()) ? t.trim() : DEFAULT_KEYSTORE_TYPE;
    }

    private String resolveAlias() {
        if (explicitAlias != null && !explicitAlias.trim().isEmpty()) {
            return explicitAlias.trim();
        }
        String a = sysPropResolver.apply(VaultConstants.SYS_PROP_KEYSTORE_ALIAS);
        if (a != null && !a.trim().isEmpty()) {
            return a.trim();
        }
        a = envResolver.apply(VaultConstants.ENV_KEYSTORE_ALIAS);
        return (a != null && !a.trim().isEmpty()) ? a.trim() : DEFAULT_ALIAS;
    }

    @Override
    public String getProviderName() {
        return "KeyStoreKeyProvider" + (explicitPath != null ? "[" + explicitPath + "]" : "");
    }
}
