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

import umrao.tomcat.vault.cli.TomcatVaultCLI;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class TomcatVaultCLITest {

    @TempDir
    Path tempDir;

    private final InputStream originalSystemIn = System.in;

    @AfterEach
    public void tearDown() {
        System.setIn(originalSystemIn);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
    }

    @Test
    @DisplayName("TomcatVaultCLI constructor and main method")
    @SuppressWarnings("InstantiationOfUtilityClass")
    public void testCliConstructorAndMain() {
        TomcatVaultCLI cli = new TomcatVaultCLI();
        assertNotNull(cli);

        // Calling main with -h exits cleanly with code 0 (System.exit is only called on non-zero)
        TomcatVaultCLI.main("-h");
    }

    @Test
    @DisplayName("CLI execute with encryption and decryption flags")
    public void testCliExecution() {
        int exitCodeEnc = TomcatVaultCLI.execute("-e", "myCliPassword123", "-k", "myCustomTestKey321");
        assertEquals(0, exitCodeEnc, "Encryption should exit with 0");

        int exitCodeEncLong = TomcatVaultCLI.execute("--encrypt", "myCliPassword123", "--key", "myCustomTestKey321");
        assertEquals(0, exitCodeEncLong);

        // Decrypt valid
        VaultCrypto crypto = new VaultCrypto("myCustomTestKey321");
        String ciphertext = crypto.encrypt("myCliPassword123");

        int exitCodeDec = TomcatVaultCLI.execute("-d", ciphertext, "-k", "myCustomTestKey321");
        assertEquals(0, exitCodeDec);

        int exitCodeDecLong = TomcatVaultCLI.execute("--decrypt", ciphertext, "-k", "myCustomTestKey321");
        assertEquals(0, exitCodeDecLong);

        // Decrypt corrupted ciphertext triggers exception catch block
        int exitCodeCorrupted = TomcatVaultCLI.execute("-d", "ENC(corruptedBase64!#)", "-k", "myCustomTestKey321");
        assertEquals(1, exitCodeCorrupted);
    }

    @Test
    @DisplayName("CLI execute with --env, --keyfile, and --legacy options")
    public void testCliAdvancedOptions() throws Exception {
        // --env with valid and missing arg
        assertEquals(0, TomcatVaultCLI.execute("-e", "secret", "--env", "PATH"));
        assertEquals(1, TomcatVaultCLI.execute("-e", "secret", "--env"));

        // --keyfile with valid and missing arg
        File tempKey = File.createTempFile("vault-cli", ".key");
        tempKey.deleteOnExit();
        try (FileOutputStream fos = new FileOutputStream(tempKey)) {
            fos.write("FileSecretKey999\n".getBytes(StandardCharsets.UTF_8));
        }

        assertEquals(0, TomcatVaultCLI.execute("-e", "secret", "--keyfile", tempKey.getAbsolutePath()));
        assertEquals(1, TomcatVaultCLI.execute("-e", "secret", "--keyfile"));

        // --key missing arg
        assertEquals(1, TomcatVaultCLI.execute("-e", "secret", "-k"));

        // --legacy flag
        assertEquals(0, TomcatVaultCLI.execute("-e", "secret", "--legacy"));

        // Positional message argument with -e and -d followed by flag
        assertEquals(0, TomcatVaultCLI.execute("-e", "-k", "myKey", "positionalSecret"));
        assertEquals(1, TomcatVaultCLI.execute("-d", "-k", "myKey", "ENC(corruptedCipher)"));

        // Whitespace only message
        assertEquals(1, TomcatVaultCLI.execute("-e", "   "));
    }

    @Test
    @DisplayName("CLI stdin reading pipeline and IO errors")
    public void testCliStdin() {
        // Feed secret via stdin
        ByteArrayInputStream bais = new ByteArrayInputStream("pipeSecretPassword\n".getBytes(StandardCharsets.UTF_8));
        System.setIn(bais);

        assertEquals(0, TomcatVaultCLI.execute("-e", "-"));

        // Stdin empty
        ByteArrayInputStream emptyBais = new ByteArrayInputStream("".getBytes(StandardCharsets.UTF_8));
        System.setIn(emptyBais);
        assertEquals(1, TomcatVaultCLI.execute("-e", "-"));

        // Stdin throwing IOException
        System.setIn(new InputStream() {
            @Override
            public int read() throws java.io.IOException {
                throw new java.io.IOException("Simulated broken pipe");
            }
        });
        assertEquals(1, TomcatVaultCLI.execute("-e", "-"));
    }

    @Test
    @DisplayName("CLI help and missing argument validation")
    public void testCliHelpAndValidation() {
        assertEquals(0, TomcatVaultCLI.execute("-h"));
        assertEquals(0, TomcatVaultCLI.execute("--help"));

        assertEquals(1, TomcatVaultCLI.execute((String[]) null));
        assertEquals(1, TomcatVaultCLI.execute());

        // Neither -e nor -d specified
        assertEquals(1, TomcatVaultCLI.execute("-k", "someKey"));

        // Missing argument for --debug-log
        assertEquals(1, TomcatVaultCLI.execute("-e", "test", "--debug-log"));
    }

    @Test
    @DisplayName("CLI execute with --debug-log and --debug options")
    void testCliDebugLogOptions() {
        File debugFile = new File("build/tmp/cli-debug.log");
        int exitCode = TomcatVaultCLI.execute("-e", "myPassword", "-k", "myKey123", "--debug-log", debugFile.getAbsolutePath());
        assertEquals(0, exitCode);
        umrao.tomcat.vault.logging.VaultLogFactory.closeFileHandlers();
        assertTrue(debugFile.exists());

        // Test --debug flag
        int exitCodeDebug = TomcatVaultCLI.execute("-e", "myPassword", "-k", "myKey123", "--debug");
        assertEquals(0, exitCodeDebug);
        umrao.tomcat.vault.logging.VaultLogFactory.closeFileHandlers();
    }

    @Test
    @DisplayName("CLI execute with --diagnose option")
    void testCliDiagnose() {
        int exitCode = TomcatVaultCLI.execute("--diagnose");
        assertEquals(0, exitCode);

        int exitCodeCustom = TomcatVaultCLI.execute("diagnose", "-k", "CustomProdKey12345");
        assertEquals(0, exitCodeCustom);
    }

    @Test
    @DisplayName("CLI: --generate-key generates 256-bit Hex and Base64 keys")
    void testCliGenerateKey() {
        assertEquals(0, TomcatVaultCLI.execute("--generate-key"));
        assertEquals(0, TomcatVaultCLI.execute("generate-key"));
    }

    @Test
    @DisplayName("CLI: re-encrypt single ciphertext with old and new key")
    void testCliReEncryptSingleCiphertext() {
        VaultCrypto oldCrypto = new VaultCrypto("OldMasterKey123");
        String ciphertext = oldCrypto.encrypt("DatabasePassword99");

        int code = TomcatVaultCLI.execute(
                "re-encrypt", ciphertext,
                "--old-key", "OldMasterKey123",
                "--new-key", "NewMasterKey456",
                "--new-alias", "v2"
        );
        assertEquals(0, code);
    }

    @Test
    @DisplayName("CLI: re-encrypt context.xml file in place with backup")
    void testCliReEncryptContextXml() throws Exception {
        VaultCrypto oldCrypto = new VaultCrypto("OldKey789");
        String encUser = oldCrypto.encrypt("app_user");
        String encPass = oldCrypto.encrypt("app_secret_pass");

        String xmlContent = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<Context>\n"
                + "  <Resource name=\"jdbc/RotateDB\"\n"
                + "            auth=\"Container\"\n"
                + "            type=\"javax.sql.DataSource\"\n"
                + "            username=\"" + encUser + "\"\n"
                + "            password=\"" + encPass + "\"\n"
                + "            url=\"jdbc:h2:mem:rotatedb\" />\n"
                + "</Context>";

        File xmlFile = tempDir.resolve("context_to_rotate.xml").toFile();
        Files.writeString(xmlFile.toPath(), xmlContent);

        int code = TomcatVaultCLI.execute(
                "re-encrypt",
                "--context", xmlFile.getAbsolutePath(),
                "--old-key", "OldKey789",
                "--new-key", "NewKey999",
                "--new-alias", "v2"
        );
        assertEquals(0, code);

        // Verify backup was created
        File bakFile = new File(xmlFile.getAbsolutePath() + ".bak");
        assertTrue(bakFile.exists());

        // Verify updated XML decrypts with NewKey999
        VaultCrypto newCrypto = new VaultCrypto("NewKey999");
        String updatedXml = Files.readString(xmlFile.toPath());
        assertTrue(updatedXml.contains("ENC(v2:"));
        assertFalse(updatedXml.contains(encPass));
        int start = updatedXml.indexOf("ENC(v2:");
        int end = updatedXml.indexOf("\"", start);
        String decrypted = newCrypto.decrypt(updatedXml.substring(start, end));
        assertTrue("app_secret_pass".equals(decrypted) || "app_user".equals(decrypted));
    }

    @Test
    @DisplayName("CLI: re-encrypt error handling (missing arguments, invalid file)")
    void testCliReEncryptErrorCases() {
        // Missing --new-key
        assertEquals(1, TomcatVaultCLI.execute("re-encrypt", "--context", "dummy.xml"));

        // Missing context/message
        assertEquals(1, TomcatVaultCLI.execute("re-encrypt", "--new-key", "key123"));

        // Non-existent context file
        assertEquals(1, TomcatVaultCLI.execute("re-encrypt", "--context", tempDir.resolve("missing.xml").toString(), "--new-key", "key123"));

        // CLI --strict option
        assertEquals(0, TomcatVaultCLI.execute("-e", "testVal", "-k", "myCustomKey", "--strict"));
    }
}
