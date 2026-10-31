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

package org.apache.tomcat.vault.key;

import org.apache.tomcat.vault.VaultConstants;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Resolves the encryption key from an external file on the filesystem.
 * The file path can be specified via system property {@code tomcat.vault.keyfile},
 * environment variable {@code TOMCAT_VAULT_KEYFILE}, or explicit path in constructor.
 */
public class FileKeyProvider implements KeyProvider {

    private static final Logger LOGGER = Logger.getLogger(FileKeyProvider.class.getName());
    private final String explicitPath;
    private final Function<String, String> sysPropResolver;
    private final Function<String, String> envResolver;

    private volatile String cachedKey = null;
    private volatile long lastModified = -1;
    private volatile long lastFileSize = -1;
    private final Object reloadLock = new Object();

    public FileKeyProvider() {
        this(null, System::getProperty, System::getenv);
    }

    public FileKeyProvider(String explicitPath) {
        this(explicitPath, System::getProperty, System::getenv);
    }

    public FileKeyProvider(String explicitPath, Function<String, String> sysPropResolver, Function<String, String> envResolver) {
        this.explicitPath = explicitPath;
        this.sysPropResolver = sysPropResolver != null ? sysPropResolver : System::getProperty;
        this.envResolver = envResolver != null ? envResolver : System::getenv;
    }

    @Override
    public String getKey() {
        String path = resolveFilePath(null);
        if (path == null) {
            return null;
        }
        return readKeyWithAutoReload(new File(path));
    }

    @Override
    public String getKey(String keyAlias) {
        if (keyAlias == null || keyAlias.trim().isEmpty()) {
            return getKey();
        }
        String path = resolveFilePath(keyAlias.trim());
        if (path == null) {
            return getKey();
        }
        File file = new File(path);
        if (file.exists() && file.isFile()) {
            return readKeyWithAutoReload(file);
        }
        return getKey();
    }

    private String resolveFilePath(String alias) {
        if (alias != null && !alias.isEmpty()) {
            String sanitized = alias.replace('-', '_').replace('.', '_').toUpperCase();
            String path = sysPropResolver.apply(VaultConstants.SYS_PROP_KEYFILE + "." + alias);
            if (path != null && !path.trim().isEmpty()) {
                return path.trim();
            }
            path = envResolver.apply(VaultConstants.ENV_KEYFILE + "_" + sanitized);
            if (path != null && !path.trim().isEmpty()) {
                return path.trim();
            }
            if (explicitPath != null && !explicitPath.trim().isEmpty()) {
                File aliasFile = new File(explicitPath.trim() + "." + alias);
                if (aliasFile.exists() && aliasFile.isFile()) {
                    return aliasFile.getAbsolutePath();
                }
            }
        }

        String path = explicitPath;
        if (path == null || path.trim().isEmpty()) {
            path = sysPropResolver.apply(VaultConstants.SYS_PROP_KEYFILE);
        }
        if (path == null || path.trim().isEmpty()) {
            path = envResolver.apply(VaultConstants.ENV_KEYFILE);
        }
        return (path != null && !path.trim().isEmpty()) ? path.trim() : null;
    }

    private String readKeyWithAutoReload(File file) {
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            LOGGER.log(Level.WARNING, "Key file configured but cannot be read as a file: {0}", file.getAbsolutePath());
            return null;
        }

        long currentModified = file.lastModified();
        long currentSize = file.length();

        // Check if cached key is fresh
        if (cachedKey != null && currentModified == lastModified && currentSize == lastFileSize) {
            return cachedKey;
        }

        synchronized (reloadLock) {
            if (cachedKey != null && currentModified == lastModified && currentSize == lastFileSize) {
                return cachedKey;
            }
            try {
                byte[] bytes = Files.readAllBytes(file.toPath());
                String key = new String(bytes, StandardCharsets.UTF_8).trim();
                Arrays.fill(bytes, (byte) 0);
                this.cachedKey = key;
                this.lastModified = currentModified;
                this.lastFileSize = currentSize;
                LOGGER.log(Level.INFO, "Loaded/Reloaded key from file: {0}", file.getAbsolutePath());
                return key;
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to read key file: " + file.getAbsolutePath(), e);
                return cachedKey;
            }
        }
    }

    @Override
    public String getProviderName() {
        return "FileKeyProvider" + (explicitPath != null ? "[" + explicitPath + "]" : "");
    }
}
