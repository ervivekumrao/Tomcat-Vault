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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import umrao.tomcat.vault.cli.TomcatVaultCLI;
import umrao.tomcat.vault.jmx.VaultJmxSanitizer;
import umrao.tomcat.vault.key.CompositeKeyProvider;
import umrao.tomcat.vault.refresh.VaultCredentialReloader;
import umrao.tomcat.vault.secret.SecretResolverRegistry;

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class VaultSecurityIntegrationTest {

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
        System.clearProperty(VaultConstants.SYS_PROP_KEYFILE);
        System.clearProperty("aws.secret.proddb.password");
        VaultCredentialReloader.getInstance().clearListeners();
    }

    @Test
    @DisplayName("Security: Strict mode prevents fallback to development key in VaultCrypto")
    void testStrictModeFailSecureInVaultCrypto() {
        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        VaultCrypto crypto = new VaultCrypto(new CompositeKeyProvider());

        // Without external key, strict mode MUST throw SecurityException
        assertThrows(SecurityException.class, () -> crypto.encrypt("SuperSecret"));
        assertThrows(SecurityException.class, () -> crypto.decrypt("ENC(fakePayload)"));

        // If explicit key is set to default dev key in strict mode, it MUST also reject
        VaultCrypto cryptoDevKey = new VaultCrypto(VaultConstants.DEFAULT_DEV_KEY);
        assertThrows(SecurityException.class, () -> cryptoDevKey.encrypt("SuperSecret"));
    }

    @Test
    @DisplayName("Security: CompositeKeyProvider propagates SecurityException in strict mode")
    void testCompositeKeyProviderPropagatesSecurityException() {
        System.setProperty(VaultConstants.SYS_PROP_STRICT, "true");
        CompositeKeyProvider composite = new CompositeKeyProvider();
        assertThrows(SecurityException.class, composite::getKey);
        assertThrows(SecurityException.class, () -> composite.getKey("v1"));
    }

    @Test
    @DisplayName("Feature: Embedded ENC(...) decryption inside composite JDBC URLs and connection properties")
    void testEmbeddedTokenDecryption() {
        VaultCrypto crypto = new VaultCrypto("EnterpriseTestMasterKey202612345");
        String encPass = crypto.encrypt("myDatabasePassword123!");
        String encUser = crypto.encrypt("app_admin_user");

        // 1. Direct embedded check
        assertTrue(crypto.hasEmbeddedEncrypted("jdbc:postgresql://db:5432/orders?password=" + encPass));
        assertFalse(crypto.hasEmbeddedEncrypted("jdbc:postgresql://db:5432/orders?password=plaintext"));

        // 2. Embedded replacement in URL
        String compositeUrl = "jdbc:postgresql://db.corp.net:5432/orders?user=" + encUser + "&password=" + encPass + "&ssl=true";
        String decryptedUrl = crypto.decryptEmbedded(compositeUrl);

        assertEquals("jdbc:postgresql://db.corp.net:5432/orders?user=app_admin_user&password=myDatabasePassword123!&ssl=true", decryptedUrl);

        // 3. JNDI ReferencePropertyDecryptor decodes embedded attributes in place
        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("url", compositeUrl));
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor(crypto);
        decryptor.decryptProperties(ref);

        assertEquals("jdbc:postgresql://db.corp.net:5432/orders?user=app_admin_user&password=myDatabasePassword123!&ssl=true",
                ref.get("url").getContent());
    }

    @Test
    @DisplayName("Feature: Embedded cloud secret expression resolution inside JDBC URL")
    void testEmbeddedCloudSecretResolution() {
        System.setProperty("aws.secret.proddb.password", "CloudResolvedPass999");
        String rawUrl = "jdbc:mysql://aurora-cluster.internal:3306/db?user=app&password=AWS_SECRET(proddb#password)&timeout=30";

        assertTrue(SecretResolverRegistry.getInstance().hasResolvable(rawUrl));
        String resolved = SecretResolverRegistry.getInstance().resolveEmbedded(rawUrl);
        assertEquals("jdbc:mysql://aurora-cluster.internal:3306/db?user=app&password=CloudResolvedPass999&timeout=30", resolved);

        // ReferencePropertyDecryptor handles embedded cloud secret expressions
        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("url", rawUrl));
        new ReferencePropertyDecryptor().decryptProperties(ref);

        assertEquals("jdbc:mysql://aurora-cluster.internal:3306/db?user=app&password=CloudResolvedPass999&timeout=30",
                ref.get("url").getContent());
    }

    @Test
    @DisplayName("Security: Comprehensive URL sanitization across MySQL, SQL Server, Oracle, DB2, PostgreSQL")
    void testComprehensiveUrlSanitization() {
        // MySQL / MariaDB query parameters
        assertEquals("jdbc:mysql://localhost:3306/db?user=root&password=******&ssl=false",
                VaultJmxSanitizer.sanitizeUrl("jdbc:mysql://localhost:3306/db?user=root&password=ClearSecret123&ssl=false"));

        // SQL Server semicolon parameters
        assertEquals("jdbc:sqlserver://dbhost:1433;databaseName=appdb;user=sa;password=******;encrypt=true;",
                VaultJmxSanitizer.sanitizeUrl("jdbc:sqlserver://dbhost:1433;databaseName=appdb;user=sa;password=P@ssw0rd123;encrypt=true;"));

        // Oracle thin scott/tiger format
        assertEquals("jdbc:oracle:thin:scott/******@//localhost:1521/xe",
                VaultJmxSanitizer.sanitizeUrl("jdbc:oracle:thin:scott/tiger123@//localhost:1521/xe"));

        // Oracle TNS descriptor format
        assertEquals("jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc))(SECURITY=(PASSWORD=******)))",
                VaultJmxSanitizer.sanitizeUrl("jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc))(SECURITY=(PASSWORD=TigerSecret)))"));

        // Standard URI user:pass@host format
        assertEquals("jdbc:postgresql://dbuser:******@dbhost.internal:5432/proddb",
                VaultJmxSanitizer.sanitizeUrl("jdbc:postgresql://dbuser:superSecretPassword@dbhost.internal:5432/proddb"));
    }

    @Test
    @DisplayName("Memory Leak Prevention: VaultCredentialReloader uses WeakReferences and allows unregistration")
    void testCredentialReloaderMemoryLeakPrevention() {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();
        reloader.clearListeners();

        Object pool1 = new Object();
        Object pool2 = new Object();

        reloader.registerDataSource("jdbc/Pool1", pool1);
        reloader.registerDataSource("jdbc/Pool2", pool2);
        // Duplicate registration should be idempotent
        reloader.registerDataSource("jdbc/Pool1", pool1);

        assertEquals(2, reloader.getRegisteredDataSourceCount());

        // Unregister by resource name
        reloader.unregisterDataSource("jdbc/Pool1");
        assertEquals(1, reloader.getRegisteredDataSourceCount());

        // Unregister by object
        reloader.unregisterDataSource(pool2);
        assertEquals(0, reloader.getRegisteredDataSourceCount());
    }

    @Test
    @DisplayName("Pool Eviction: DBCP2 restart/evict is invoked upon credential reload")
    void testDbcp2PoolEviction() {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();
        reloader.clearListeners();

        AtomicBoolean restarted = new AtomicBoolean(false);
        Object mockDbcpPool = new Object() {
            @SuppressWarnings("unused")
            public void restart() {
                restarted.set(true);
            }
        };

        reloader.registerDataSource("jdbc/DbcpPool", mockDbcpPool);
        reloader.notifyReload("jdbc/DbcpPool");

        assertTrue(restarted.get(), "DBCP2 restart() should be invoked when credentials reload");
    }

    @Test
    @DisplayName("CLI: --benchmark and --mask commands execute successfully")
    void testCliBenchmarkAndMask() {
        // 1. CLI --benchmark
        int benchmarkExit = TomcatVaultCLI.execute("--benchmark", "-k", "BenchmarkMasterKey1234567890123");
        assertEquals(0, benchmarkExit);

        // 2. CLI --mask
        int maskExit = TomcatVaultCLI.execute("--mask", "jdbc:mysql://localhost:3306/db?user=app&password=SecretPassword!");
        assertEquals(0, maskExit);
    }
}
