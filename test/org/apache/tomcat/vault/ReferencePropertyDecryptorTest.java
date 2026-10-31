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

package org.apache.tomcat.vault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class ReferencePropertyDecryptorTest {

    @Test
    @DisplayName("Constructors branch coverage")
    public void testConstructors() {
        ReferencePropertyDecryptor defaultDecryptor = new ReferencePropertyDecryptor();
        assertNotNull(defaultDecryptor);

        ReferencePropertyDecryptor nullCryptoDecryptor = new ReferencePropertyDecryptor(null);
        assertNotNull(nullCryptoDecryptor);
    }

    @Test
    @DisplayName("decryptProperties null and empty references")
    public void testNullAndEmptyReference() {
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        decryptor.decryptProperties(null);

        Reference emptyRef = new Reference("javax.sql.DataSource");
        decryptor.decryptProperties(emptyRef);
        assertEquals(0, emptyRef.size());
    }

    @Test
    @DisplayName("Decrypts encrypted attributes in JNDI Reference while leaving plaintext intact")
    public void testDecryptPropertiesInReference() {
        VaultCrypto crypto = new VaultCrypto("TestKeyForReference123");
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor(crypto);

        String rawPassword = "dbMasterPassword#2026";
        String rawUsername = "oracle_admin";
        String rawUrl = "jdbc:oracle:thin:@localhost:1521/XEPDB1";

        String encPassword = crypto.encrypt(rawPassword);
        String encUsername = crypto.encrypt(rawUsername);

        Reference reference = new Reference("javax.sql.DataSource");
        reference.add(new StringRefAddr("driverClassName", "oracle.jdbc.OracleDriver"));
        reference.add(new StringRefAddr("username", encUsername));
        reference.add(new StringRefAddr("password", encPassword));
        reference.add(new StringRefAddr("url", rawUrl)); // unencrypted
        reference.add(new StringRefAddr("maxActive", "50"));

        decryptor.decryptProperties(reference);

        Map<String, String> properties = new HashMap<>();
        Enumeration<RefAddr> enumeration = reference.getAll();
        while (enumeration.hasMoreElements()) {
            RefAddr addr = enumeration.nextElement();
            properties.put(addr.getType(), addr.getContent().toString());
        }

        assertEquals("oracle.jdbc.OracleDriver", properties.get("driverClassName"));
        assertEquals(rawUsername, properties.get("username"), "Username should be decrypted");
        assertEquals(rawPassword, properties.get("password"), "Password should be decrypted");
        assertEquals(rawUrl, properties.get("url"), "Unencrypted URL should remain untouched");
        assertEquals("50", properties.get("maxActive"));
    }

    @Test
    @DisplayName("RefAddr edge cases: null content, null type, corrupted ciphertext")
    public void testRefAddrEdgeCases() {
        VaultCrypto crypto = new VaultCrypto("TestKeyEdgeCases");
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor(crypto);

        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new RefAddr("nullContentProp") {
            @Override
            public Object getContent() {
                return null;
            }
        });
        ref.add(new RefAddr(null) {
            @Override
            public Object getContent() {
                return "someVal";
            }
        });

        // Test with FINE logging enabled to cover Level.FINE and Level.INFO branches
        java.util.logging.Logger logger = java.util.logging.Logger.getLogger(ReferencePropertyDecryptor.class.getName());
        java.util.logging.Level oldLevel = logger.getLevel();
        logger.setLevel(java.util.logging.Level.FINEST);
        try {
            decryptor.decryptProperties(ref);
        } finally {
            logger.setLevel(oldLevel);
        }

        // Test where decryptedValue equals rawValue
        VaultCrypto identityCrypto = new VaultCrypto("TestKey") {
            @Override
            public boolean isEncrypted(String val) {
                return true;
            }
            @Override
            public String decrypt(String val) {
                return val; // identity
            }
        };
        ReferencePropertyDecryptor identityDecryptor = new ReferencePropertyDecryptor(identityCrypto);
        Reference identityRef = new Reference("javax.sql.DataSource");
        identityRef.add(new StringRefAddr("password", "ENC(same)"));
        identityDecryptor.decryptProperties(identityRef);
        assertEquals("ENC(same)", identityRef.get("password").getContent().toString());

        // Corrupted ciphertext throwing RuntimeException
        Reference corruptRef = new Reference("javax.sql.DataSource");
        corruptRef.add(new StringRefAddr("password", "ENC(corruptedBase64)"));
        assertThrows(RuntimeException.class, () -> decryptor.decryptProperties(corruptRef));
    }

    @Test
    @DisplayName("isSensitive method test")
    public void testIsSensitive() {
        assertFalse(ReferencePropertyDecryptor.isSensitive(null));
        assertTrue(ReferencePropertyDecryptor.isSensitive("password"));
        assertTrue(ReferencePropertyDecryptor.isSensitive("dbPwd"));
        assertTrue(ReferencePropertyDecryptor.isSensitive("username"));
        assertTrue(ReferencePropertyDecryptor.isSensitive("user"));
        assertTrue(ReferencePropertyDecryptor.isSensitive("jdbcUrl"));
        assertTrue(ReferencePropertyDecryptor.isSensitive("connectionProperties"));
        assertFalse(ReferencePropertyDecryptor.isSensitive("maxActive"));
    }
}
