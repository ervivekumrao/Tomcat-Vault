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

import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Hashtable;

/**
 * High-performance JNDI ObjectFactory for HikariCP connection pools in Apache Tomcat.
 * Intercepts connection pool definitions in {@code context.xml} or {@code server.xml},
 * decrypts encrypted credentials (such as {@code dataSource.password}, {@code password},
 * {@code dataSource.user}, and {@code jdbcUrl}), and delegates to HikariCP's JNDI factory.
 */
public class VaultHikariDataSourceFactory implements ObjectFactory {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultHikariDataSourceFactory.class);
    private static final String HIKARI_JNDI_FACTORY_CLASS = "com.zaxxer.hikari.HikariJNDIFactory";

    private final ReferencePropertyDecryptor decryptor;
    private final ObjectFactory delegateFactory;

    // Instance-level cached factory to eliminate static ClassLoader memory leaks across context lifecycles
    private volatile ObjectFactory cachedHikariFactory = null;
    private final Object hikariLock = new Object();

    public VaultHikariDataSourceFactory() {
        this(new ReferencePropertyDecryptor(), null);
    }

    public VaultHikariDataSourceFactory(ReferencePropertyDecryptor decryptor) {
        this(decryptor, null);
    }

    public VaultHikariDataSourceFactory(ReferencePropertyDecryptor decryptor, ObjectFactory delegateFactory) {
        this.decryptor = decryptor != null ? decryptor : new ReferencePropertyDecryptor();
        this.delegateFactory = delegateFactory;
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        if (obj instanceof Reference ref) {
            decryptor.decryptProperties(ref);
        }

        if (delegateFactory != null) {
            return delegateFactory.getObjectInstance(obj, name, nameCtx, environment);
        }

        // Delegate to HikariCP's HikariJNDIFactory with thread-safe instance caching
        ObjectFactory factory = cachedHikariFactory;
        if (factory == null) {
            synchronized (hikariLock) {
                factory = cachedHikariFactory;
                if (factory == null) {
                    try {
                        ClassLoader cl = Thread.currentThread().getContextClassLoader();
                        if (cl == null) {
                            cl = getClass().getClassLoader();
                        }
                        Class<?> hikariFactoryClass = Class.forName(HIKARI_JNDI_FACTORY_CLASS, true, cl);
                        Object factoryInstance = hikariFactoryClass.getDeclaredConstructor().newInstance();
                        if (factoryInstance instanceof ObjectFactory) {
                            factory = (ObjectFactory) factoryInstance;
                        } else {
                            final Method method = hikariFactoryClass.getMethod("getObjectInstance", Object.class, Name.class, Context.class, Hashtable.class);
                            factory = (o, n, c, env) -> {
                                try {
                                    return method.invoke(factoryInstance, o, n, c, env);
                                } catch (InvocationTargetException ite) {
                                    Throwable target = ite.getTargetException() != null ? ite.getTargetException() : ite;
                                    if (target instanceof Exception) {
                                        throw (Exception) target;
                                    }
                                    throw new RuntimeException(target);
                                }
                            };
                        }
                        cachedHikariFactory = factory;
                    } catch (ClassNotFoundException e) {
                        LOGGER.error("HikariCP JNDI Factory (" + HIKARI_JNDI_FACTORY_CLASS + ") not found on classpath. Ensure HikariCP.jar is placed in Tomcat's lib/ directory.", e);
                        throw e;
                    }
                }
            }
        }

        try {
            return factory.getObjectInstance(obj, name, nameCtx, environment);
        } catch (InvocationTargetException ite) {
            Throwable target = ite.getTargetException() != null ? ite.getTargetException() : ite;
            if (target instanceof Exception) {
                throw (Exception) target;
            }
            throw new RuntimeException(target);
        }
    }
}
