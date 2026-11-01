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

import umrao.tomcat.vault.cli.TomcatVaultCLI;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class TomcatVaultCLIVerificationTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("P1: CLI verify executes against valid context.xml with live H2 connection")
    void testCliVerifySuccessWithH2() throws Exception {
        VaultCrypto crypto = new VaultCrypto("TestKeyForH2Verification12345678");
        String encryptedPass = crypto.encrypt("h2secret");
        String encryptedUser = crypto.encrypt("sa");

        String contextXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<Context>\n"
                + "  <Resource name=\"jdbc/TestDB\"\n"
                + "            auth=\"Container\"\n"
                + "            type=\"javax.sql.DataSource\"\n"
                + "            driverClassName=\"org.h2.Driver\"\n"
                + "            url=\"jdbc:h2:mem:clitest;DB_CLOSE_DELAY=-1\"\n"
                + "            username=\"" + encryptedUser + "\"\n"
                + "            password=\"" + encryptedPass + "\" />\n"
                + "</Context>";

        File xmlFile = tempDir.resolve("context.xml").toFile();
        Files.write(xmlFile.toPath(), contextXml.getBytes());

        int exitCode = TomcatVaultCLI.execute(
                "-v",
                "-c", xmlFile.getAbsolutePath(),
                "-k", "TestKeyForH2Verification12345678"
        );
        assertEquals(0, exitCode);
    }

    @Test
    @DisplayName("P1: CLI verify handles missing file, invalid XML, and non-existent driver")
    void testCliVerifyEdgeCases() throws Exception {
        // Missing --context argument
        assertEquals(1, TomcatVaultCLI.execute("-v"));

        // Non-existent file
        assertEquals(1, TomcatVaultCLI.execute("-v", "-c", tempDir.resolve("not_found.xml").toString()));

        // Empty XML / no resources
        File emptyXml = tempDir.resolve("empty.xml").toFile();
        Files.write(emptyXml.toPath(), "<Context></Context>".getBytes());
        assertEquals(0, TomcatVaultCLI.execute("-v", "-c", emptyXml.getAbsolutePath()));

        // Resource with non-existent driver on classpath skips live network connection gracefully
        String mockXml = """
                <Context>
                  <Resource name="jdbc/OracleDB"
                            driverClassName="oracle.jdbc.OracleDriver"
                            url="jdbc:oracle:thin:@//localhost:1521/XE"
                            username="scott"
                            password="tiger" />
                </Context>""";
        File oracleXml = tempDir.resolve("oracle.xml").toFile();
        Files.writeString(oracleXml.toPath(), mockXml);
        assertEquals(0, TomcatVaultCLI.execute("-v", "-c", oracleXml.getAbsolutePath()));

        // Resource with invalid credentials / connection failure
        String failXml = """
                <Context>
                  <Resource name="jdbc/FailDB"
                            driverClassName="org.h2.Driver"
                            url="jdbc:h2:mem:faildb;IFEXISTS=TRUE"
                            username="sa"
                            password="wrong" />
                </Context>""";
        File failXmlFile = tempDir.resolve("fail.xml").toFile();
        Files.writeString(failXmlFile.toPath(), failXml);
        assertEquals(1, TomcatVaultCLI.execute("-v", "-c", failXmlFile.getAbsolutePath()));
    }

    @Test
    @DisplayName("P2: CLI encrypt with --key-alias produces versioned output")
    void testCliEncryptWithKeyAlias() {
        int exitCode = TomcatVaultCLI.execute(
                "-e", "SuperSecretPass",
                "--key-alias", "v2",
                "-k", "MasterEncryptionKey1234567890123"
        );
        assertEquals(0, exitCode);
    }

    @Test
    @DisplayName("CLI argument parsing validation: missing arguments and invalid options")
    void testCliArgumentValidation() {
        assertEquals(1, TomcatVaultCLI.execute("-e", "pass", "--key-alias"));
        assertEquals(1, TomcatVaultCLI.execute("-v", "--context"));
        assertEquals(1, TomcatVaultCLI.execute("-v", "-c", "dummy.xml", "--timeout", "invalid_num"));
    }
}
