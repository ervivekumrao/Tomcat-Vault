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

package umrao.tomcat.vault.key;

import umrao.tomcat.vault.VaultConstants;
import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * Resolves the encryption key from an external file on the filesystem.
 * The file path can be specified via system property {@code tomcat.vault.keyfile},
 * environment variable {@code TOMCAT_VAULT_KEYFILE}, or explicit path in constructor.
 * Enforces POSIX permission warnings and automatically detects key file changes for Kubernetes Secret mounts.
 */
public class FileKeyProvider implements KeyProvider {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(FileKeyProvider.class);
    private final String explicitPath;
    private final Function<String, String> sysPropResolver;
    private final Function<String, String> envResolver;

    private static final class FileCacheEntry {
        final String key;
        final long lastModified;
        final long lastFileSize;

        FileCacheEntry(String key, long lastModified, long lastFileSize) {
            this.key = key;
            this.lastModified = lastModified;
            this.lastFileSize = lastFileSize;
        }
    }

    private final Map<String, FileCacheEntry> fileCache = new ConcurrentHashMap<>();
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

    private void checkFilePermissions(File file) {
        try {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file.toPath());
                boolean insecure = perms.contains(PosixFilePermission.OTHERS_READ)
                        || perms.contains(PosixFilePermission.OTHERS_WRITE)
                        || perms.contains(PosixFilePermission.GROUP_WRITE);
                if (insecure) {
                    String warning = "[SECURITY WARNING] Insecure permissions on key file: " + file.getAbsolutePath() +
                            ". Key file is accessible by other users or group-writable. Recommended permissions are 0600 (owner read-only).";
                    LOGGER.warn(warning);
                    boolean isStrict = Boolean.getBoolean(VaultConstants.SYS_PROP_STRICT)
                            || "true".equalsIgnoreCase(System.getenv(VaultConstants.ENV_STRICT));
                    if (isStrict) {
                        throw new SecurityException("Strict mode violation: " + warning);
                    }
                }
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Exception ignored) {
            // Non-POSIX platform (e.g. Windows) or permission read failure
        }
    }

    private String readKeyWithAutoReload(File file) {
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            LOGGER.warn("Key file configured but cannot be read as a file: " + file.getAbsolutePath());
            return null;
        }

        checkFilePermissions(file);

        String absPath = file.getAbsolutePath();
        long currentModified = file.lastModified();
        long currentSize = file.length();

        FileCacheEntry entry = fileCache.get(absPath);
        if (entry != null && currentModified == entry.lastModified && currentSize == entry.lastFileSize) {
            return entry.key;
        }

        synchronized (reloadLock) {
            entry = fileCache.get(absPath);
            currentModified = file.lastModified();
            currentSize = file.length();
            if (entry != null && currentModified == entry.lastModified && currentSize == entry.lastFileSize) {
                return entry.key;
            }
            try {
                byte[] bytes = Files.readAllBytes(file.toPath());
                String key = new String(bytes, StandardCharsets.UTF_8).trim();
                Arrays.fill(bytes, (byte) 0);
                fileCache.put(absPath, new FileCacheEntry(key, currentModified, currentSize));
                umrao.tomcat.vault.VaultCrypto.clearKeyCache();
                LOGGER.info("Loaded/Reloaded key from file: " + absPath);
                return key;
            } catch (IOException e) {
                LOGGER.error("Failed to read key file: " + absPath, e);
                return entry != null ? entry.key : null;
            }
        }
    }

    @Override
    public String getProviderName() {
        return "FileKeyProvider" + (explicitPath != null ? "[" + explicitPath + "]" : "");
    }
}
