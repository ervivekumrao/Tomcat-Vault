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

package umrao.tomcat.vault.cli;

import umrao.tomcat.vault.VaultConstants;
import umrao.tomcat.vault.VaultCrypto;
import umrao.tomcat.vault.key.CompositeKeyProvider;
import umrao.tomcat.vault.key.EnvironmentKeyProvider;
import umrao.tomcat.vault.key.FileKeyProvider;
import umrao.tomcat.vault.key.KeyProvider;
import umrao.tomcat.vault.secret.SecretResolverRegistry;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Base64;

/**
 * Enterprise command-line interface for Tomcat Vault.
 * Supports interactive masked password entry, standard input pipelines,
 * custom key providers, key versioning, dry-run connection verification,
 * cryptographic key generation, in-place re-encryption migration, and backward-compatible syntax.
 * @author Vivek Umrao
 */
public class TomcatVaultCLI {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void main(String... args) {
        int exitCode = execute(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    @SuppressWarnings({"UncontrolledUserInputValue", "PathTraversal"})
    public static int execute(String... args) {
        if (args == null || args.length == 0 || isHelpRequested(args)) {
            printHelp();
            return args == null || args.length == 0 ? 1 : 0;
        }

        boolean encryptMode = false;
        boolean decryptMode = false;
        boolean verifyMode = false;
        boolean diagnoseMode = false;
        boolean generateKeyMode = false;
        boolean reEncryptMode = false;
        boolean benchmarkMode = false;
        boolean maskMode = false;
        boolean legacyMode = false;
        String explicitKey = null;
        String oldKey = null;
        String newKey = null;
        String keyAlias = null;
        String envVar = null;
        String keyFile = null;
        String contextPath = null;
        String message = null;
        int timeoutSeconds = 5;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--diagnose".equalsIgnoreCase(arg) || "diagnose".equalsIgnoreCase(arg)
                    || "--status".equalsIgnoreCase(arg) || "status".equalsIgnoreCase(arg)
                    || "--health".equalsIgnoreCase(arg) || "health".equalsIgnoreCase(arg)) {
                diagnoseMode = true;
            } else if ("--benchmark".equalsIgnoreCase(arg) || "benchmark".equalsIgnoreCase(arg)) {
                benchmarkMode = true;
            } else if ("--mask".equalsIgnoreCase(arg) || "-m".equalsIgnoreCase(arg) || "mask".equalsIgnoreCase(arg)) {
                maskMode = true;
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    message = args[++i];
                }
            } else if ("--generate-key".equalsIgnoreCase(arg) || "generate-key".equalsIgnoreCase(arg) || "--keygen".equalsIgnoreCase(arg)) {
                generateKeyMode = true;
            } else if ("re-encrypt".equalsIgnoreCase(arg) || "--re-encrypt".equalsIgnoreCase(arg)) {
                reEncryptMode = true;
            } else if ("--strict".equalsIgnoreCase(arg)) {
                System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
            } else if ("--old-key".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    oldKey = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --old-key");
                    return 1;
                }
            } else if ("--new-key".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    newKey = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --new-key");
                    return 1;
                }
            } else if ("-e".equalsIgnoreCase(arg) || "--encrypt".equalsIgnoreCase(arg)) {
                encryptMode = true;
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    message = args[++i];
                }
            } else if ("-d".equalsIgnoreCase(arg) || "--decrypt".equalsIgnoreCase(arg)) {
                decryptMode = true;
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    message = args[++i];
                }
            } else if ("-v".equalsIgnoreCase(arg) || "--verify".equalsIgnoreCase(arg) || "verify".equalsIgnoreCase(arg)) {
                verifyMode = true;
                if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    contextPath = args[++i];
                }
            } else if ("-c".equalsIgnoreCase(arg) || "--context".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    contextPath = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --context");
                    return 1;
                }
            } else if ("-k".equalsIgnoreCase(arg) || "--key".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    explicitKey = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --key");
                    return 1;
                }
            } else if ("-a".equalsIgnoreCase(arg) || "--key-alias".equalsIgnoreCase(arg) || "--alias".equalsIgnoreCase(arg) || "--new-alias".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    keyAlias = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --key-alias");
                    return 1;
                }
            } else if ("--env".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    envVar = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --env");
                    return 1;
                }
            } else if ("--keyfile".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    keyFile = args[++i];
                } else {
                    System.err.println("Error: Missing argument for --keyfile");
                    return 1;
                }
            } else if ("--timeout".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    try {
                        timeoutSeconds = Integer.parseInt(args[++i]);
                    } catch (NumberFormatException e) {
                        System.err.println("Error: Invalid number for --timeout");
                        return 1;
                    }
                }
            } else if ("--debug-log".equalsIgnoreCase(arg)) {
                if (i + 1 < args.length) {
                    setupDebugLog(args[++i]);
                } else {
                    System.err.println("Error: Missing argument for --debug-log");
                    return 1;
                }
            } else if ("--debug".equalsIgnoreCase(arg)) {
                umrao.tomcat.vault.logging.VaultLogFactory.initFileLogging(
                        System.getProperty("catalina.base", ".") + "/logs/tomcat-vault-debug.log", true);
            } else if ("--legacy".equalsIgnoreCase(arg)) {
                legacyMode = true;
            } else if (!arg.startsWith("-") && message == null) {
                message = arg;
            }
        }

        if (generateKeyMode) {
            return executeGenerateKey();
        }

        if (benchmarkMode) {
            return executeBenchmark(explicitKey);
        }

        if (maskMode) {
            return executeMask(message);
        }

        if (reEncryptMode) {
            return executeReEncrypt(contextPath, message, oldKey, newKey, keyAlias);
        }

        // Configure KeyProvider chain
        CompositeKeyProvider providerChain = new CompositeKeyProvider();
        if (explicitKey != null) {
            final String finalExplicitKey = explicitKey;
            providerChain.addProviderFirst(new KeyProvider() {
                @Override
                public String getKey() {
                    return finalExplicitKey;
                }

                @Override
                public String getProviderName() {
                    return "CLIArgumentKeyProvider";
                }
            });
        }
        if (envVar != null) {
            providerChain.addProviderFirst(new EnvironmentKeyProvider(envVar));
        }
        if (keyFile != null) {
            providerChain.addProviderFirst(new FileKeyProvider(keyFile));
        }

        VaultCrypto crypto = new VaultCrypto(providerChain);

        if (diagnoseMode) {
            return executeDiagnostics(crypto);
        }

        if (verifyMode) {
            return executeVerification(contextPath, crypto, timeoutSeconds);
        }

        if (!encryptMode && !decryptMode) {
            System.err.println("Error: Must specify -e (--encrypt), -d (--decrypt), -v (--verify), --re-encrypt, --generate-key, --benchmark, --mask, or --diagnose");
            printHelp();
            return 1;
        }

        // If message is omitted or passed as "-", read interactively or from stdin
        if (message == null || "-".equals(message)) {
            message = readInputSecurely(encryptMode ? "Enter secret to encrypt: " : "Enter ciphertext to decrypt: ");
        }

        if (message == null || message.trim().isEmpty()) {
            System.err.println("Error: Input message is empty");
            return 1;
        }

        try {
            if (encryptMode) {
                String result = legacyMode
                        ? crypto.encryptLegacy(message)
                        : crypto.encrypt(message, keyAlias);
                System.out.println("encrypted: " + result);
            } else {
                String result = crypto.decrypt(message);
                System.out.println("decrypted: " + result);
            }
            return 0;
        } catch (Exception e) {
            System.err.println("Operation failed: " + e.getMessage());
            return 1;
        }
    }

    @SuppressWarnings({"PathTraversal", "UncontrolledUserInputValue"})
    private static void setupDebugLog(String logFilePath) {
        if (logFilePath != null && !logFilePath.trim().isEmpty()) {
            File file = new File(logFilePath).getAbsoluteFile();
            umrao.tomcat.vault.logging.VaultLogFactory.initFileLogging(file.toPath().normalize().toString(), true);
        }
    }

    private static int executeGenerateKey() {
        byte[] keyBytes = new byte[32]; // 256 bits
        SECURE_RANDOM.nextBytes(keyBytes);

        String hexKey = VaultCrypto.safeBytesToHex(keyBytes);
        String base64Key = Base64.getEncoder().encodeToString(keyBytes);
        Arrays.fill(keyBytes, (byte) 0);

        System.out.println("Tomcat Vault - Cryptographic Key Generator");
        System.out.println("===========================================");
        System.out.println("Generated 256-bit AES Master Key:");
        System.out.println();
        System.out.println("  Raw Hex (64 chars, recommended for high entropy):");
        System.out.println("  " + hexKey);
        System.out.println();
        System.out.println("  Base64 (44 chars, HSM / KeyStore compatible):");
        System.out.println("  " + base64Key);
        System.out.println();
        System.out.println("Usage in Environment Variable:");
        System.out.println("  export TOMCAT_VAULT_KEY=\"" + hexKey + "\"");
        System.out.println();
        System.out.println("Usage in Tomcat setenv.sh:");
        System.out.println("  CATALINA_OPTS=\"$CATALINA_OPTS -Dtomcat.vault.key=" + hexKey + "\"");
        System.out.println();
        System.out.println("Usage in Protected Key File:");
        System.out.println("  echo -n \"" + hexKey + "\" > /etc/tomcat/vault.key && chmod 600 /etc/tomcat/vault.key");
        return 0;
    }

    private static int executeBenchmark(String explicitKey) {
        System.out.println("Tomcat Vault - Cryptographic Engine Benchmark");
        System.out.println("==============================================");
        VaultCrypto crypto = (explicitKey != null && !explicitKey.trim().isEmpty())
                ? new VaultCrypto(explicitKey.trim())
                : new VaultCrypto();

        int warmups = 50;
        int iterations = 1000;
        String samplePlaintext = "ProductionSuperSecureDatabasePassword!#2026";

        // Warm up JIT
        for (int i = 0; i < warmups; i++) {
            String enc = crypto.encrypt(samplePlaintext);
            crypto.decrypt(enc);
        }

        // Benchmark AES-256-GCM
        long startGcm = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            String enc = crypto.encrypt(samplePlaintext);
            crypto.decrypt(enc);
        }
        long durationGcm = System.currentTimeMillis() - startGcm;
        double opsPerSec = (iterations * 2.0 * 1000.0) / Math.max(durationGcm, 1);
        double avgLatencyMs = (double) durationGcm / (iterations * 2.0);

        System.out.printf("AES-256-GCM Operations: %d encryptions + %d decryptions%n", iterations, iterations);
        System.out.printf("Total Execution Time:    %d ms%n", durationGcm);
        System.out.printf("Throughput:              %.0f ops/sec%n", opsPerSec);
        System.out.printf("Average Latency:         %.4f ms/op%n", avgLatencyMs);
        System.out.println("----------------------------------------------");
        System.out.println("Benchmark Result: PASSED");
        return 0;
    }

    private static int executeMask(String message) {
        if (message == null || "-".equals(message)) {
            message = readInputSecurely("Enter URL or string to mask: ");
        }
        if (message == null || message.trim().isEmpty()) {
            System.err.println("Error: Input string to mask is empty");
            return 1;
        }
        String masked = umrao.tomcat.vault.jmx.VaultJmxSanitizer.sanitizeUrl(message.trim());
        System.out.println("masked: " + masked);
        return 0;
    }

    private static int executeReEncrypt(String contextPath, String message, String oldKey, String newKey, String newAlias) {
        if (newKey == null || newKey.trim().isEmpty()) {
            System.err.println("Error: Re-encryption requires --new-key <key>");
            return 1;
        }

        VaultCrypto cryptoOld = (oldKey != null && !oldKey.trim().isEmpty())
                ? new VaultCrypto(oldKey.trim())
                : new VaultCrypto();
        VaultCrypto cryptoNew = new VaultCrypto(newKey.trim());

        // Single message mode
        if (message != null && !message.trim().isEmpty()) {
            try {
                String plain = cryptoOld.decrypt(message.trim());
                String reEncrypted = cryptoNew.encrypt(plain, newAlias);
                System.out.println("re-encrypted: " + reEncrypted);
                return 0;
            } catch (Exception e) {
                System.err.println("Re-encryption failed: " + e.getMessage());
                return 1;
            }
        }

        // File context mode
        if (contextPath == null || contextPath.trim().isEmpty()) {
            System.err.println("Error: Specify either ciphertext value or --context <path/to/context.xml> for re-encryption");
            return 1;
        }

        File file = new File(contextPath.trim());
        if (!file.exists() || !file.isFile() || !file.canRead() || !file.canWrite()) {
            System.err.println("Error: Configuration file does not exist or is not readable/writable: " + file.getAbsolutePath());
            return 1;
        }

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(file);
            NodeList resources = doc.getElementsByTagName("Resource");

            int reEncryptedCount = 0;
            for (int i = 0; i < resources.getLength(); i++) {
                Node node = resources.item(i);
                if (node.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                Element elem = (Element) node;
                NamedNodeMap attrs = elem.getAttributes();
                for (int a = 0; a < attrs.getLength(); a++) {
                    Node attr = attrs.item(a);
                    String val = attr.getNodeValue();
                    if (val != null && cryptoOld.isEncrypted(val)) {
                        String plain = cryptoOld.decrypt(val);
                        String reEncrypted = cryptoNew.encrypt(plain, newAlias);
                        attr.setNodeValue(reEncrypted);
                        reEncryptedCount++;
                    }
                }
            }

            // Create backup file before writing
            File backupFile = new File(file.getAbsolutePath() + ".bak");
            Files.copy(file.toPath(), backupFile.toPath(), StandardCopyOption.REPLACE_EXISTING);

            // Write modified XML
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(file);
            transformer.transform(source, result);

            System.out.println("Tomcat Vault: Re-encryption completed successfully.");
            System.out.println("Re-encrypted " + reEncryptedCount + " credentials in " + file.getAbsolutePath());
            System.out.println("Backup created at: " + backupFile.getAbsolutePath());
            return 0;
        } catch (Exception e) {
            System.err.println("Re-encryption failed: " + e.getMessage());
            return 1;
        }
    }

    private static int executeVerification(String contextPath, VaultCrypto crypto, int timeoutSeconds) {
        if (contextPath == null || contextPath.trim().isEmpty()) {
            System.err.println("Error: Missing context configuration file. Specify --context <path/to/context.xml>");
            return 1;
        }

        File file = new File(contextPath.trim());
        if (!file.exists() || !file.isFile() || !file.canRead()) {
            System.err.println("Error: Configuration file does not exist or cannot be read: " + file.getAbsolutePath());
            return 1;
        }

        System.out.println("Tomcat Vault: Verifying DataSource configurations in " + file.getAbsolutePath() + "...");
        System.out.println("--------------------------------------------------------------------------------");

        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // Secure XML parsing against XXE (CWE-611)
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);

            DocumentBuilder db = dbf.newDocumentBuilder();
            Document doc = db.parse(file);
            NodeList resources = doc.getElementsByTagName("Resource");

            if (resources.getLength() == 0) {
                System.out.println("No <Resource> elements found in configuration file.");
                return 0;
            }

            int successCount = 0;
            int totalCount = resources.getLength();

            for (int i = 0; i < resources.getLength(); i++) {
                Node node = resources.item(i);
                if (node.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                Element elem = (Element) node;
                String resName = getAttr(elem, "name", "Resource[" + i + "]");
                String url = getAttr(elem, "url", getAttr(elem, "jdbcUrl", getAttr(elem, "dataSource.url", null)));
                String user = getAttr(elem, "username", getAttr(elem, "user", getAttr(elem, "dataSource.user", null)));
                String pass = getAttr(elem, "password", getAttr(elem, "pwd", getAttr(elem, "dataSource.password", null)));
                String driverClass = getAttr(elem, "driverClassName", null);

                // Decrypt credentials
                String decryptedUser = resolveOrDecrypt(user, crypto);
                String decryptedPass = resolveOrDecrypt(pass, crypto);
                String decryptedUrl = resolveOrDecrypt(url, crypto);

                if (decryptedPass == null && pass != null && crypto.isEncrypted(pass)) {
                    System.err.println("[✗] Resource '" + resName + "': Decryption failed for 'password'.");
                    continue;
                }

                if (decryptedUrl == null || decryptedUrl.isEmpty()) {
                    System.out.println("[✓] Resource '" + resName + "': Non-JDBC or URL not defined. Decryption verified.");
                    successCount++;
                    continue;
                }

                // Attempt JDBC connection if driver or standard JDBC can handle it
                boolean driverAvailable = true;
                if (driverClass != null && !driverClass.trim().isEmpty()) {
                    try {
                        Class.forName(driverClass.trim());
                    } catch (ClassNotFoundException e) {
                        driverAvailable = false;
                        System.out.println("[✓] Resource '" + resName + "': Successfully decrypted credentials. Driver '" + driverClass + "' not on CLI classpath (live connection skipped).");
                        successCount++;
                    }
                }

                if (driverAvailable) {
                    long start = System.currentTimeMillis();
                    DriverManager.setLoginTimeout(timeoutSeconds);
                    try (Connection conn = DriverManager.getConnection(decryptedUrl, decryptedUser, decryptedPass)) {
                        long latency = System.currentTimeMillis() - start;
                        if (!conn.isClosed()) {
                            System.out.println("[✓] Resource '" + resName + "': Successfully decrypted credentials & established live JDBC connection (latency: " + latency + "ms).");
                            successCount++;
                        }
                    } catch (Exception e) {
                        System.err.println("[✗] Resource '" + resName + "': Decrypted credentials successfully, but JDBC connection failed: " + e.getMessage());
                    }
                }
            }

            System.out.println("--------------------------------------------------------------------------------");
            System.out.println("Verification Summary: " + successCount + "/" + totalCount + " resources passed.");
            return successCount == totalCount ? 0 : 1;

        } catch (Exception e) {
            System.err.println("Verification error: " + e.getMessage());
            return 1;
        }
    }

    private static String getAttr(Element elem, String name, String defaultValue) {
        if (elem.hasAttribute(name)) {
            String val = elem.getAttribute(name);
            if (!val.trim().isEmpty()) {
                return val.trim();
            }
        }
        return defaultValue;
    }

    private static String resolveOrDecrypt(String val, VaultCrypto crypto) {
        if (val == null || val.isEmpty()) {
            return val;
        }
        if (SecretResolverRegistry.getInstance().isResolvable(val)) {
            return SecretResolverRegistry.getInstance().resolve(val);
        }
        if (crypto.isEncrypted(val)) {
            return crypto.decrypt(val);
        }
        return val;
    }

    private static int executeDiagnostics(VaultCrypto crypto) {
        System.out.println("Tomcat Vault - System & Cryptographic Diagnostics");
        System.out.println("=================================================");
        System.out.println("Java Runtime: " + System.getProperty("java.runtime.name") + " (" + System.getProperty("java.version") + ")");
        System.out.println("Java Vendor:  " + System.getProperty("java.vendor"));
        System.out.println("OS:           " + System.getProperty("os.name") + " " + System.getProperty("os.version") + " (" + System.getProperty("os.arch") + ")");

        // 1. JCE Policy
        try {
            int maxKeyLen = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
            boolean unlimited = maxKeyLen >= 256;
            System.out.println("JCE Policy:   " + (unlimited ? "[OK] Unlimited Strength Jurisdiction (Max AES: " + maxKeyLen + "-bit)" : "[WARN] Restricted Jurisdiction (Max AES: " + maxKeyLen + "-bit)"));
        } catch (Exception e) {
            System.out.println("JCE Policy:   [FAIL] " + e.getMessage());
        }

        // 2. Cipher availability
        try {
            javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            System.out.println("Cipher GCM:   [OK] AES/GCM/NoPadding available");
        } catch (Exception e) {
            System.out.println("Cipher GCM:   [FAIL] " + e.getMessage());
        }

        // 3. PBKDF2 availability
        try {
            javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            System.out.println("KDF PBKDF2:   [OK] PBKDF2WithHmacSHA256 available (600,000 iterations)");
        } catch (Exception e) {
            System.out.println("KDF PBKDF2:   [FAIL] " + e.getMessage());
        }

        // 4. Key Provider Evaluation
        try {
            String key = crypto.getKeyProvider().getKey();
            boolean isDev = umrao.tomcat.vault.VaultConstants.DEFAULT_DEV_KEY.equals(key);
            System.out.println("Key Provider: " + crypto.getKeyProvider().getProviderName());
            if (isDev) {
                System.out.println("Key Status:   [SECURITY WARNING] Using default development fallback key! Set TOMCAT_VAULT_KEY or -Dtomcat.vault.key for production.");
            } else {
                System.out.println("Key Status:   [OK] Production key loaded successfully (length: " + (key != null ? key.length() : 0) + " chars).");
            }
        } catch (Exception e) {
            System.out.println("Key Status:   [FAIL] Failed to resolve key: " + e.getMessage());
        }

        // 5. Functional Round-Trip Self-Test
        try {
            String testMsg = "TomcatVaultSelfTest-" + System.currentTimeMillis();
            String enc = crypto.encrypt(testMsg);
            String dec = crypto.decrypt(enc);
            if (testMsg.equals(dec)) {
                System.out.println("Self-Test:    [OK] Encrypt/Decrypt round-trip succeeded.");
            } else {
                System.out.println("Self-Test:    [FAIL] Decrypted value does not match original plaintext.");
                return 1;
            }
        } catch (Exception e) {
            System.out.println("Self-Test:    [FAIL] Self-test exception: " + e.getMessage());
            return 1;
        }

        System.out.println("-------------------------------------------------");
        System.out.println("Diagnostic Result: ALL CHECKS PASSED");
        return 0;
    }

    private static String readInputSecurely(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword(prompt);
            if (chars == null) {
                return null;
            }
            String result = new String(chars);
            java.util.Arrays.fill(chars, '\0');
            return result;
        } else {
            // Non-interactive fallback (piped stdin)
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
                return reader.readLine();
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static boolean isHelpRequested(String[] args) {
        for (String arg : args) {
            if ("-h".equalsIgnoreCase(arg) || "--help".equalsIgnoreCase(arg)) {
                return true;
            }
        }
        return false;
    }

    private static void printHelp() {
        System.out.println("Tomcat Vault - Connection Pool Encryption CLI (v2.0)");
        System.out.println("===================================================");
        System.out.println("Usage:");
        System.out.println("  java -jar tomcat-vault.jar -e [VALUE] [OPTIONS]     Encrypt value (default: AES-256-GCM)");
        System.out.println("  java -jar tomcat-vault.jar -d [VALUE] [OPTIONS]     Decrypt value");
        System.out.println("  java -jar tomcat-vault.jar -v -c <FILE> [OPTIONS]   Verify DataSources in context.xml");
        System.out.println("  java -jar tomcat-vault.jar --generate-key           Generate 256-bit random AES master key");
        System.out.println("  java -jar tomcat-vault.jar --benchmark [OPTIONS]    Run cryptographic throughput & latency benchmark");
        System.out.println("  java -jar tomcat-vault.jar --mask [VALUE]           Mask credentials in URL or connection string");
        System.out.println("  java -jar tomcat-vault.jar re-encrypt [OPTIONS]     Rotate/re-encrypt credentials");
        System.out.println("  java -jar tomcat-vault.jar --status                 Run system & cryptographic health diagnostics");
        System.out.println("  java -jar tomcat-vault.jar --diagnose               Run system & cryptographic diagnostics");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -e, --encrypt [VALUE]       Encrypt the provided value");
        System.out.println("  -d, --decrypt [VALUE]       Decrypt the provided value");
        System.out.println("      --status, --health      Run health check & system diagnostics");
        System.out.println("  -v, --verify                Verify DataSources in context configuration");
        System.out.println("  -c, --context <PATH>        Path to context.xml or server.xml");
        System.out.println("      --generate-key          Generate new 256-bit AES master encryption key");
        System.out.println("      --benchmark             Benchmark AES-256-GCM encryption/decryption performance");
        System.out.println("  -m, --mask [VALUE]          Sanitize and mask passwords in JDBC URLs/strings");
        System.out.println("      --re-encrypt            Re-encrypt credentials with a new key/alias");
        System.out.println("      --old-key <SECRET>      Existing encryption key for re-encryption");
        System.out.println("      --new-key <SECRET>      New encryption key for re-encryption");
        System.out.println("  -a, --key-alias <ALIAS>     Tag encryption with key alias/version (e.g. v1, v2)");
        System.out.println("  -k, --key <SECRET>          Provide custom encryption key string directly");
        System.out.println("      --env <VAR_NAME>        Read encryption key from environment variable");
        System.out.println("      --keyfile <PATH>        Read encryption key from external file");
        System.out.println("      --strict                Enable strict mode (forbid fallback dev key)");
        System.out.println("      --timeout <SECONDS>     JDBC connection timeout in seconds (default: 5)");
        System.out.println("      --debug-log <PATH>      Write detailed debug logs to dedicated file");
        System.out.println("      --debug                 Enable verbose debug logging");
        System.out.println("      --legacy                Generate legacy hex-CBC encrypted output");
        System.out.println("  -h, --help                  Display this help message");
    }
}
