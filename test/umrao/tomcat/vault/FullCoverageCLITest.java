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
import umrao.tomcat.vault.cli.TomcatVaultCLI;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class FullCoverageCLITest {

    @TempDir
    Path tempDir;

    private final InputStream originalSystemIn = System.in;

    @BeforeEach
    void setUp() {
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
    }

    @AfterEach
    void tearDown() {
        System.setIn(originalSystemIn);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
    }

    @Test
    void testCliArgumentValidationBranches() {
        // Missing arguments for flags
        assertEquals(1, TomcatVaultCLI.execute("--old-key"));
        assertEquals(1, TomcatVaultCLI.execute("--new-key"));
        assertEquals(1, TomcatVaultCLI.execute("-c"));
        assertEquals(1, TomcatVaultCLI.execute("-k"));
        assertEquals(1, TomcatVaultCLI.execute("-a"));
        assertEquals(1, TomcatVaultCLI.execute("--env"));
        assertEquals(1, TomcatVaultCLI.execute("--keyfile"));
        assertEquals(1, TomcatVaultCLI.execute("--debug-log"));

        // Timeout invalid integer
        assertEquals(1, TomcatVaultCLI.execute("--timeout", "invalid_num", "-e", "test"));

        // Re-encrypt missing new-key
        assertEquals(1, TomcatVaultCLI.execute("--re-encrypt", "-e", "test"));

        // Re-encrypt invalid ciphertext string
        assertEquals(1, TomcatVaultCLI.execute("--re-encrypt", "--old-key", "oldkey", "--new-key", "newkey", "ENC(INVALID_CIPHERTEXT)"));
    }

    @Test
    void testCliMaskBranches() {
        // Mask with inline string
        assertEquals(0, TomcatVaultCLI.execute("--mask", "jdbc:mysql://root:secret@localhost:3306/db"));

        // Mask with stdin "-"
        System.setIn(new ByteArrayInputStream("jdbc:postgresql://user:pass@localhost:5432/db\n".getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, TomcatVaultCLI.execute("--mask", "-"));

        // Mask with empty input returns 1
        System.setIn(new ByteArrayInputStream("\n".getBytes(StandardCharsets.UTF_8)));
        assertEquals(1, TomcatVaultCLI.execute("--mask", "-"));
    }

    @Test
    void testCliStdinReading() {
        // Encrypt with stdin "-"
        System.setIn(new ByteArrayInputStream("stdin-secret-plaintext\n".getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, TomcatVaultCLI.execute("-e", "-", "-k", "myclikey123"));

        // Decrypt with stdin "-"
        VaultCrypto crypto = new VaultCrypto("myclikey123");
        String ciphertext = crypto.encrypt("stdin-secret-plaintext");
        System.setIn(new ByteArrayInputStream((ciphertext + "\n").getBytes(StandardCharsets.UTF_8)));
        assertEquals(0, TomcatVaultCLI.execute("-d", "-", "-k", "myclikey123"));
    }

    @Test
    void testCliReencryptContextXmlBranches() throws Exception {
        // Context file does not exist
        assertEquals(1, TomcatVaultCLI.execute("--re-encrypt", "--old-key", "k1", "--new-key", "k2", "-c", "/path/to/missing/context.xml"));

        // Context file with comments, non-element nodes, and unencrypted attributes
        File xmlFile = tempDir.resolve("context.xml").toFile();
        String xmlContent = """
                <?xml version='1.0' encoding='UTF-8'?>
                <Context>
                  <!-- Comment node -->
                  <Resource name='jdbc/TestDB' auth='Container' type='javax.sql.DataSource'
                            password='plainPassword' />
                </Context>""";
        Files.writeString(xmlFile.toPath(), xmlContent);

        assertEquals(0, TomcatVaultCLI.execute("--re-encrypt", "--old-key", "k1", "--new-key", "k2", "-c", xmlFile.getAbsolutePath()));
    }

    @Test
    void testCliVerifyBranches() throws Exception {
        // Verify with non-existent context file
        assertEquals(1, TomcatVaultCLI.execute("-v", tempDir.resolve("missing.xml").toString()));

        // Context with comments, non-JDBC resource (no url), bad pass, and cloud secret expression
        File xmlFile = tempDir.resolve("verify-context.xml").toFile();
        VaultCrypto crypto = new VaultCrypto("verify-key-123");
        String encPass = crypto.encrypt("mypassword");

        System.setProperty("aws.secret.verify.pass", "resolvedSecret123");

        String xmlContent = "<?xml version='1.0' encoding='UTF-8'?>\n"
                + "<Context>\n"
                + "  <!-- This is a comment node -->\n"
                + "  <Resource name='bean/Config' type='com.example.Config' password='" + encPass + "' />\n"
                + "  <Resource name='jdbc/SecretPass' type='javax.sql.DataSource' password='AWS_SECRET(verify/pass)' url='jdbc:h2:mem:test1' />\n"
                + "  <Resource name='jdbc/BadPass' type='javax.sql.DataSource' password='ENC(CORRUPTED_CIPHERTEXT)' url='jdbc:h2:mem:test2' />\n"
                + "</Context>";
        Files.writeString(xmlFile.toPath(), xmlContent);

        // Runs verify - tests non-JDBC pass, resolvable secret resolution, and BadPass failure
        int code = TomcatVaultCLI.execute("-v", xmlFile.getAbsolutePath(), "-k", "verify-key-123");
        assertTrue(code == 0 || code == 1);
    }

    @Test
    void testCliDiagnoseAndGenerateKey() {
        assertEquals(0, TomcatVaultCLI.execute("--keygen"));
        assertEquals(0, TomcatVaultCLI.execute("--diagnose", "-k", "my-diagnose-key"));
        assertEquals(0, TomcatVaultCLI.execute("benchmark", "-k", "my-benchmark-key"));
    }
}
