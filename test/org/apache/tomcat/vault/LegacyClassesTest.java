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
import umrao.encrypt.Constants;
import umrao.encrypt.EncryptDecrypt;
import umrao.encrypt.Encryption;

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;

import static org.junit.jupiter.api.Assertions.*;

public class LegacyClassesTest {

    @Test
    @DisplayName("Constants private constructor reflection test")
    public void testConstantsConstructor() throws Exception {
        Constructor<Constants> constructor = Constants.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        Constants instance = constructor.newInstance();
        assertNotNull(instance);

        assertEquals("AES", Constants.ENCRYPTION_ALGO);
        assertEquals(VaultConstants.DEFAULT_DEV_KEY, Constants.ENCRYPTION_KEY);
        assertEquals(VaultConstants.DEFAULT_DEV_IV, Constants.IV);
        assertEquals("SHA-512", Constants.HASHING_ALGO);
    }

    @Test
    @DisplayName("VaultConstants private constructor reflection test")
    public void testVaultConstantsConstructor() throws Exception {
        Constructor<VaultConstants> constructor = VaultConstants.class.getDeclaredConstructor();
        assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        constructor.setAccessible(true);
        VaultConstants instance = constructor.newInstance();
        assertNotNull(instance);

        assertEquals("AES/GCM/NoPadding", VaultConstants.ALGORITHM_AES_GCM);
        assertEquals("AES/CBC/PKCS5Padding", VaultConstants.ALGORITHM_AES_CBC_LEGACY);
    }

    @Test
    @DisplayName("umrao.encrypt.Encryption full facade test")
    public void testEncryptionFacade() {
        Encryption defaultEnc = new Encryption();
        assertNotNull(defaultEnc);

        Encryption customEnc = new Encryption("MyCustomKey123", "AES");
        assertNotNull(customEnc);

        Encryption nullEnc = new Encryption(null, null);
        assertNotNull(nullEnc);

        Encryption emptyEnc = new Encryption("", "");
        assertNotNull(emptyEnc);

        // getEncryptedMessage & getDecryptedMessage
        String plain = "HelloLegacyEncryption2026";
        String encrypted = customEnc.getEncryptedMessage(plain);
        assertNotNull(encrypted);
        assertEquals(plain, customEnc.getDecryptedMessage(encrypted));

        // Validation exceptions
        assertThrows(RuntimeException.class, () -> customEnc.getEncryptedMessage(null));
        assertThrows(RuntimeException.class, () -> customEnc.getEncryptedMessage(""));
        assertThrows(RuntimeException.class, () -> customEnc.getDecryptedMessage(null));
        assertThrows(RuntimeException.class, () -> customEnc.getDecryptedMessage(""));

        // Helper methods
        assertNotNull(customEnc.generateStaticSecretKey());
        assertNotNull(customEnc.getIvParameterSpec());

        // decryptProperties
        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("password", encrypted));
        customEnc.decryptProperties(ref);
        assertEquals(plain, ref.get("password").getContent().toString());
    }

    @Test
    @DisplayName("umrao.encrypt.EncryptDecrypt main delegation test")
    public void testEncryptDecryptMain() {
        EncryptDecrypt instance = new EncryptDecrypt();
        assertNotNull(instance);

        // Calling main with -h should execute cleanly without error
        EncryptDecrypt.main("-h");
    }
}
