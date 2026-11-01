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
import umrao.tomcat.vault.refresh.VaultCredentialReloader;

import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.naming.spi.ObjectFactory;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.sql.SQLException;
import java.util.Hashtable;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Vivek Umrao
 */
public class FullCoverageDataSourceFactoryTest {

    private ClassLoader originalCl;

    @BeforeEach
    void setUp() {
        originalCl = Thread.currentThread().getContextClassLoader();
    }

    @AfterEach
    void tearDown() {
        Thread.currentThread().setContextClassLoader(originalCl);
    }

    @SuppressWarnings("unused")
    public static class CustomNonObjectFactory {
        public Object getObjectInstance(Object o, Name n, Context c, Hashtable<?, ?> env) throws Exception {
            if ("fail_checked".equals(o)) {
                throw new SQLException("Custom DB failure");
            }
            if ("fail_error".equals(o)) {
                throw new AssertionError("Custom fatal error");
            }
            return "CustomNonObjectFactoryResult";
        }
    }

    public static class ThrowingObjectFactory implements ObjectFactory {
        @Override
        public Object getObjectInstance(Object o, Name n, Context c, Hashtable<?, ?> env) throws Exception {
            if ("target_error".equals(o)) {
                throw new InvocationTargetException(new AssertionError("Fatal error wrapped"));
            }
            throw new InvocationTargetException(new SQLException("SQL error wrapped"));
        }
    }

    @Test
    void testVaultDataSourceFactoryBranches() throws Exception {
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        VaultDataSourceFactory factory = new VaultDataSourceFactory(decryptor);

        // Non-reference object
        assertNull(factory.getObjectInstance("non-ref", null, null, null));

        // Result and name registration branches
        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("username", "testuser"));
        CompositeName name = new CompositeName("jdbc/TestDS");

        // Null result and non-null name -> no exception
        Object res1 = factory.getObjectInstance("plain-string", name, null, null);
        assertNull(res1);

        // Non-null result with null name -> no exception
        Reference refValid = new Reference("javax.sql.DataSource");
        refValid.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        refValid.add(new StringRefAddr("url", "jdbc:h2:mem:testds1"));
        Object res2 = factory.getObjectInstance(refValid, null, null, null);
        assertNotNull(res2);

        // Non-null result with non-null name -> registers with VaultCredentialReloader
        Object res3 = factory.getObjectInstance(refValid, name, null, null);
        assertNotNull(res3);
        assertTrue(VaultCredentialReloader.getInstance().getRegisteredDataSourceCount() > 0);
    }

    @Test
    void testVaultBasicDataSourceFactoryBranches() throws Exception {
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        VaultBasicDataSourceFactory factory = new VaultBasicDataSourceFactory(decryptor);

        // Non-reference object
        assertNull(factory.getObjectInstance("non-ref", null, null, null));

        // Non-null result with name
        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("url", "jdbc:h2:mem:basicds"));
        CompositeName name = new CompositeName("jdbc/BasicDS");

        Object res = factory.getObjectInstance(ref, name, null, null);
        assertNotNull(res);
        assertTrue(VaultCredentialReloader.getInstance().getRegisteredDataSourceCount() > 0);

        // Result without name
        Object resNoName = factory.getObjectInstance(ref, null, null, null);
        assertNotNull(resNoName);
    }

    @Test
    void testVaultGenericDataSourceFactoryBranches() throws Exception {
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        VaultGenericDataSourceFactory factory = new VaultGenericDataSourceFactory(decryptor, null);

        // Missing or null delegate
        Reference emptyRef = new Reference("javax.sql.DataSource");
        assertThrows(IllegalArgumentException.class, () -> factory.getObjectInstance(emptyRef, null, null, null));

        // Delegate addr with null content
        Reference nullContentRef = new Reference("javax.sql.DataSource");
        nullContentRef.add(new StringRefAddr("delegateFactory", null));
        assertThrows(IllegalArgumentException.class, () -> factory.getObjectInstance(nullContentRef, null, null, null));

        // Delegate class does not exist
        Reference badClassRef = new Reference("javax.sql.DataSource");
        badClassRef.add(new StringRefAddr("delegateFactory", "com.nonexistent.FakeFactory"));
        assertThrows(ClassNotFoundException.class, () -> factory.getObjectInstance(badClassRef, null, null, null));

        // Delegate class that does NOT implement ObjectFactory
        Reference nonObjectFactoryRef = new Reference("javax.sql.DataSource");
        nonObjectFactoryRef.add(new StringRefAddr("delegateFactory", CustomNonObjectFactory.class.getName()));
        CompositeName name = new CompositeName("jdbc/GenericDS");

        Object successResult = factory.getObjectInstance(nonObjectFactoryRef, name, null, null);
        assertEquals("CustomNonObjectFactoryResult", successResult);

        // Factory with CustomNonObjectFactory as default delegate
        VaultGenericDataSourceFactory nonObjFactory = new VaultGenericDataSourceFactory(CustomNonObjectFactory.class.getName());
        assertThrows(SQLException.class, () -> nonObjFactory.getObjectInstance("fail_checked", name, null, null));
        assertThrows(RuntimeException.class, () -> nonObjFactory.getObjectInstance("fail_error", name, null, null));

        // Factory with ThrowingObjectFactory as default delegate
        VaultGenericDataSourceFactory throwingFactory = new VaultGenericDataSourceFactory(ThrowingObjectFactory.class.getName());
        assertThrows(SQLException.class, () -> throwingFactory.getObjectInstance("any", name, null, null));
        assertThrows(RuntimeException.class, () -> throwingFactory.getObjectInstance("target_error", name, null, null));

        // ContextClassLoader is null fallback
        Thread.currentThread().setContextClassLoader(null);
        VaultGenericDataSourceFactory fallbackFactory = new VaultGenericDataSourceFactory();
        Object fallbackRes = fallbackFactory.getObjectInstance(nonObjectFactoryRef, null, null, null);
        assertEquals("CustomNonObjectFactoryResult", fallbackRes);
    }

    @Test
    void testVaultHikariDataSourceFactoryBranches() throws Exception {
        ReferencePropertyDecryptor decryptor = new ReferencePropertyDecryptor();
        VaultHikariDataSourceFactory factory = new VaultHikariDataSourceFactory(decryptor);

        // ContextClassLoader is null branch (lines 79-80)
        Thread.currentThread().setContextClassLoader(null);
        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("jdbcUrl", "jdbc:h2:mem:hikarids1"));
        CompositeName name = new CompositeName("jdbc/HikariDS");

        Object res = factory.getObjectInstance(ref, name, null, null);
        assertNotNull(res);
        assertTrue(VaultCredentialReloader.getInstance().getRegisteredDataSourceCount() > 0);

        // ClassNotFoundException branch (lines 101-103)
        ClassLoader emptyCl = new ClassLoader(null) {
            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                throw new ClassNotFoundException(name);
            }
        };
        Thread.currentThread().setContextClassLoader(emptyCl);
        VaultHikariDataSourceFactory failingFactory = new VaultHikariDataSourceFactory();
        assertThrows(ClassNotFoundException.class, () -> failingFactory.getObjectInstance(ref, null, null, null));

        // InvocationTargetException unwrapping branches (lines 112-117)
        Thread.currentThread().setContextClassLoader(originalCl);
        VaultHikariDataSourceFactory mockFactory = new VaultHikariDataSourceFactory();
        Field field = VaultHikariDataSourceFactory.class.getDeclaredField("cachedHikariFactory");
        field.setAccessible(true);

        // Target exception is Exception
        field.set(mockFactory, (ObjectFactory) (o, n, c, env) -> {
            throw new InvocationTargetException(new SQLException("Hikari DB init failure"));
        });
        assertThrows(SQLException.class, () -> mockFactory.getObjectInstance(ref, null, null, null));

        // Target exception is Error/Throwable
        field.set(mockFactory, (ObjectFactory) (o, n, c, env) -> {
            throw new InvocationTargetException(new AssertionError("Hikari fatal error"));
        });
        assertThrows(RuntimeException.class, () -> mockFactory.getObjectInstance(ref, null, null, null));
    }
}
