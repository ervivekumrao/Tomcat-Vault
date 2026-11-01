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

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.naming.spi.ObjectFactory;
import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class VaultGenericDataSourceFactoryTest {

    public static class DummyDelegateFactory implements ObjectFactory {
        @Override
        public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) {
            return "DummyDataSourceInstance";
        }
    }

    @Test
    @DisplayName("VaultGenericDataSourceFactory constructor coverage")
    void testConstructors() {
        VaultGenericDataSourceFactory f1 = new VaultGenericDataSourceFactory();
        assertNotNull(f1);

        VaultGenericDataSourceFactory f2 = new VaultGenericDataSourceFactory(DummyDelegateFactory.class.getName());
        assertNotNull(f2);

        VaultGenericDataSourceFactory f3 = new VaultGenericDataSourceFactory(new ReferencePropertyDecryptor(), DummyDelegateFactory.class.getName());
        assertNotNull(f3);
    }

    @Test
    @DisplayName("VaultGenericDataSourceFactory delegates and decrypts properties")
    void testDelegation() throws Exception {
        VaultCrypto crypto = new VaultCrypto("TestKeyForGenericPool12345678901");
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor(crypto);
        VaultGenericDataSourceFactory factory = new VaultGenericDataSourceFactory(decryptor, DummyDelegateFactory.class.getName());

        Reference ref = new Reference("javax.sql.DataSource");
        String encryptedPass = crypto.encrypt("GenericSecretPass");
        ref.add(new StringRefAddr("password", encryptedPass));

        Object result = factory.getObjectInstance(ref, null, null, new Hashtable<>());
        assertEquals("DummyDataSourceInstance", result);
        assertEquals("GenericSecretPass", ref.get("password").getContent().toString());
    }

    @Test
    @DisplayName("VaultGenericDataSourceFactory with delegateFactory attribute in Reference")
    void testDelegateFactoryAttribute() throws Exception {
        VaultGenericDataSourceFactory factory = new VaultGenericDataSourceFactory();

        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr(VaultGenericDataSourceFactory.DELEGATE_FACTORY_PROPERTY, DummyDelegateFactory.class.getName()));

        Object result = factory.getObjectInstance(ref, null, null, new Hashtable<>());
        assertEquals("DummyDataSourceInstance", result);
    }

    @Test
    @DisplayName("VaultGenericDataSourceFactory with invalid or missing delegate throws exception")
    void testInvalidDelegateThrows() {
        VaultGenericDataSourceFactory factory = new VaultGenericDataSourceFactory(null);
        assertThrows(IllegalArgumentException.class, () ->
                factory.getObjectInstance("non-ref", null, null, new Hashtable<>()));

        VaultGenericDataSourceFactory factoryInvalid = new VaultGenericDataSourceFactory("non.existent.FactoryClass");
        assertThrows(ClassNotFoundException.class, () ->
                factoryInvalid.getObjectInstance("non-ref", null, null, new Hashtable<>()));
    }
}
