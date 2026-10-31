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

package org.apache.tomcat.vault.cli;

import org.apache.tomcat.vault.VaultCrypto;
import org.apache.tomcat.vault.key.CompositeKeyProvider;
import org.apache.tomcat.vault.key.EnvironmentKeyProvider;
import org.apache.tomcat.vault.key.FileKeyProvider;
import org.apache.tomcat.vault.key.KeyProvider;
import org.apache.tomcat.vault.secret.SecretResolverRegistry;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * Enterprise command-line interface for Tomcat Vault.
 * Supports interactive masked password entry, standard input pipelines,
 * custom key providers, key versioning, dry-run connection verification,
 * and backward-compatible legacy syntax.
 */
public class TomcatVaultCLI {

    public static void main(String... args) {
        int exitCode = execute(args);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    public static int execute(String... args) {
        if (args == null || args.length == 0 || isHelpRequested(args)) {
            printHelp();
            return args == null || args.length == 0 ? 1 : 0;
        }

        boolean encryptMode = false;
        boolean decryptMode = false;
        boolean verifyMode = false;
        boolean legacyMode = false;
        String explicitKey = null;
        String keyAlias = null;
        String envVar = null;
        String keyFile = null;
        String contextPath = null;
        String message = null;
        int timeoutSeconds = 5;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("-e".equalsIgnoreCase(arg) || "--encrypt".equalsIgnoreCase(arg)) {
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
            } else if ("-a".equalsIgnoreCase(arg) || "--key-alias".equalsIgnoreCase(arg) || "--alias".equalsIgnoreCase(arg)) {
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
                    String logFile = args[++i];
                    org.apache.tomcat.vault.logging.VaultLogFactory.initFileLogging(logFile, true);
                } else {
                    System.err.println("Error: Missing argument for --debug-log");
                    return 1;
                }
            } else if ("--debug".equalsIgnoreCase(arg)) {
                org.apache.tomcat.vault.logging.VaultLogFactory.initFileLogging(
                        System.getProperty("catalina.base", ".") + "/logs/tomcat-vault-debug.log", true);
            } else if ("--legacy".equalsIgnoreCase(arg)) {
                legacyMode = true;
            } else if (!arg.startsWith("-") && message == null) {
                message = arg;
            }
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

        if (verifyMode) {
            return executeVerification(contextPath, crypto, timeoutSeconds);
        }

        if (!encryptMode && !decryptMode) {
            System.err.println("Error: Must specify -e (--encrypt), -d (--decrypt), or -v (--verify)");
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

    private static String readInputSecurely(String prompt) {
        Console console = System.console();
        if (console != null) {
            char[] chars = console.readPassword(prompt);
            if (chars == null) {
                return null;
            }
            String result = new String(chars);
            java.util.Arrays.fill(chars, ' ');
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
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -e, --encrypt [VALUE]       Encrypt the provided value");
        System.out.println("  -d, --decrypt [VALUE]       Decrypt the provided value");
        System.out.println("  -v, --verify                Verify DataSources in context configuration");
        System.out.println("  -c, --context <PATH>        Path to context.xml or server.xml for verification");
        System.out.println("  -a, --key-alias <ALIAS>     Tag encryption with key alias/version (e.g. v1, v2)");
        System.out.println("  -k, --key <SECRET>          Provide custom encryption key string directly");
        System.out.println("      --env <VAR_NAME>        Read encryption key from environment variable");
        System.out.println("      --keyfile <PATH>        Read encryption key from external file");
        System.out.println("      --timeout <SECONDS>     JDBC connection timeout in seconds (default: 5)");
        System.out.println("      --debug-log <PATH>      Write detailed debug logs to dedicated file");
        System.out.println("      --debug                 Enable verbose debug logging");
        System.out.println("      --legacy                Generate legacy hex-CBC encrypted output");
        System.out.println("  -h, --help                  Display this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Encrypt with key versioning:");
        System.out.println("  java -jar tomcat-vault.jar -e \"dbPass\" --key-alias v2");
        System.out.println();
        System.out.println("  # Verify all DataSources before restarting Tomcat:");
        System.out.println("  java -jar tomcat-vault.jar verify --context /opt/tomcat/conf/context.xml");
    }
}
