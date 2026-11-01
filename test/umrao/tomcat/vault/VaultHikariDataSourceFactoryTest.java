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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class VaultHikariDataSourceFactoryTest {

    @Test
    @DisplayName("VaultHikariDataSourceFactory constructor coverage")
    void testConstructors() {
        VaultHikariDataSourceFactory f1 = new VaultHikariDataSourceFactory();
        assertNotNull(f1);

        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        VaultHikariDataSourceFactory f2 = new VaultHikariDataSourceFactory(decryptor);
        assertNotNull(f2);

        VaultHikariDataSourceFactory f3 = new VaultHikariDataSourceFactory(null, null);
        assertNotNull(f3);
    }

    @Test
    @DisplayName("VaultHikariDataSourceFactory with mock delegate factory")
    void testWithDelegateFactory() throws Exception {
        ObjectFactory mockDelegate = (obj, name, nameCtx, environment) -> "MockHikariDataSource";

        VaultCrypto crypto = new VaultCrypto("TestKeyForHikari1234567890123456");
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor(crypto);
        VaultHikariDataSourceFactory factory = new VaultHikariDataSourceFactory(decryptor, mockDelegate);

        Reference ref = new Reference("com.zaxxer.hikari.HikariDataSource");
        String encryptedPass = crypto.encrypt("SecretHikariPass");
        ref.add(new StringRefAddr("dataSource.password", encryptedPass));
        ref.add(new StringRefAddr("dataSource.user", "appuser"));

        Object result = factory.getObjectInstance(ref, null, null, new Hashtable<>());
        assertEquals("MockHikariDataSource", result);

        // Verify password was decrypted in the Reference object before passing to delegate
        assertEquals("SecretHikariPass", ref.get("dataSource.password").getContent().toString());
        assertEquals("appuser", ref.get("dataSource.user").getContent().toString());
    }

    @Test
    @DisplayName("VaultHikariDataSourceFactory non-Reference object passes through to delegate")
    void testNonReference() throws Exception {
        ObjectFactory mockDelegate = (obj, name, nameCtx, environment) -> obj;
        VaultHikariDataSourceFactory factory = new VaultHikariDataSourceFactory(null, mockDelegate);

        Object result = factory.getObjectInstance("SimpleString", null, null, new Hashtable<>());
        assertEquals("SimpleString", result);
    }

    @Test
    @DisplayName("VaultHikariDataSourceFactory dynamically delegates to HikariJNDIFactory")
    void testDynamicHikariJNDIDelegation() throws Exception {
        VaultHikariDataSourceFactory factory = new VaultHikariDataSourceFactory();

        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("jdbcUrl", "jdbc:h2:mem:hikaritest;DB_CLOSE_DELAY=-1"));
        ref.add(new StringRefAddr("username", "sa"));
        ref.add(new StringRefAddr("password", ""));

        try (com.zaxxer.hikari.HikariDataSource ds = (com.zaxxer.hikari.HikariDataSource) factory.getObjectInstance(ref, null, null, new Hashtable<>())) {
            assertNotNull(ds);
        }
    }
}
