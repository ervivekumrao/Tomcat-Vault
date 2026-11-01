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

import umrao.tomcat.vault.logging.VaultLog;
import umrao.tomcat.vault.logging.VaultLogFactory;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.RefAddr;
import javax.naming.Reference;
import javax.naming.spi.ObjectFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Universal JNDI ObjectFactory adapter that can wrap any JDBC connection pool
 * (such as Vibur DBCP, C3P0, BoneCP, or custom enterprise pools).
 * Decrypts all sensitive properties in the {@link Reference} before passing them
 * to the delegate factory specified via the {@code delegateFactory} configuration attribute.
 * @author Vivek Umrao
 */
public class VaultGenericDataSourceFactory implements ObjectFactory {

    private static final VaultLog LOGGER = VaultLogFactory.getLog(VaultGenericDataSourceFactory.class);
    public static final String DELEGATE_FACTORY_PROPERTY = "delegateFactory";

    // Instance-level cache to prevent webapp ClassLoader leaks in Metaspace across context reloads
    private final Map<String, ObjectFactory> factoryCache = new ConcurrentHashMap<>();

    private final ReferencePropertyDecryptor decryptor;
    private final String defaultDelegateClassName;

    public VaultGenericDataSourceFactory() {
        this(new ReferencePropertyDecryptor(), "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory");
    }

    public VaultGenericDataSourceFactory(String defaultDelegateClassName) {
        this(new ReferencePropertyDecryptor(), defaultDelegateClassName);
    }

    public VaultGenericDataSourceFactory(ReferencePropertyDecryptor decryptor, String defaultDelegateClassName) {
        this.decryptor = decryptor != null ? decryptor : new ReferencePropertyDecryptor();
        this.defaultDelegateClassName = defaultDelegateClassName;
    }

    @Override
    public Object getObjectInstance(Object obj, Name name, Context nameCtx, Hashtable<?, ?> environment) throws Exception {
        String targetFactoryClassName = defaultDelegateClassName;

        if (obj instanceof Reference ref) {
            decryptor.decryptProperties(ref);

            RefAddr delegateAddr = ref.get(DELEGATE_FACTORY_PROPERTY);
            if (delegateAddr != null && delegateAddr.getContent() != null) {
                targetFactoryClassName = delegateAddr.getContent().toString().trim();
            }
        }

        if (targetFactoryClassName == null || targetFactoryClassName.isEmpty()) {
            throw new IllegalArgumentException("No delegateFactory specified for VaultGenericDataSourceFactory");
        }

        final String finalTargetClassName = targetFactoryClassName;
        ObjectFactory factory;
        try {
            factory = factoryCache.computeIfAbsent(finalTargetClassName, className -> {
                try {
                    ClassLoader cl = Thread.currentThread().getContextClassLoader();
                    if (cl == null) {
                        cl = getClass().getClassLoader();
                    }
                    Class<?> factoryClass = Class.forName(className, true, cl);
                    Object factoryInstance = factoryClass.getDeclaredConstructor().newInstance();
                    if (factoryInstance instanceof ObjectFactory) {
                        return (ObjectFactory) factoryInstance;
                    } else {
                        final Method method = factoryClass.getMethod("getObjectInstance", Object.class, Name.class, Context.class, Hashtable.class);
                        method.setAccessible(true);
                        return (o, n, c, env) -> {
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
                } catch (Exception e) {
                    LOGGER.error("Failed to delegate to factory class: " + className, e);
                    if (e instanceof RuntimeException) {
                        throw (RuntimeException) e;
                    }
                    throw new RuntimeException(e);
                }
            });
        } catch (RuntimeException e) {
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }

        Object result;
        try {
            result = factory.getObjectInstance(obj, name, nameCtx, environment);
        } catch (InvocationTargetException ite) {
            Throwable target = ite.getTargetException() != null ? ite.getTargetException() : ite;
            if (target instanceof Exception) {
                throw (Exception) target;
            }
            throw new RuntimeException(target);
        }

        if (result != null && name != null) {
            umrao.tomcat.vault.refresh.VaultCredentialReloader.getInstance().registerDataSource(name.toString(), result);
        }
        return result;
    }
}
