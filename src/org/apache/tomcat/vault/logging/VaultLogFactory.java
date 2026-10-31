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

package org.apache.tomcat.vault.logging;

import org.apache.tomcat.vault.VaultConstants;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.*;

/**
 * Factory for creating {@link VaultLog} instances.
 * Automatically delegates to Tomcat JULI ({@code org.apache.juli.logging.LogFactory})
 * when running inside Apache Tomcat, or standard Java Util Logging (JUL) otherwise.
 * Supports dedicated debug file logging via {@code -Dtomcat.vault.log.file} or {@code -Dtomcat.vault.debug=true}.
 */
@SuppressWarnings("unused")
public final class VaultLogFactory {

    private static final String JULI_LOG_FACTORY = "org.apache.juli.logging.LogFactory";
    private static final boolean HAS_TOMCAT_JULI;
    private static final List<Handler> ACTIVE_HANDLERS = new ArrayList<>();
    private static volatile Handler activeFileHandler = null;
    private static boolean fileLoggingInitialized = false;

    static {
        boolean juliAvailable = false;
        try {
            Class.forName(JULI_LOG_FACTORY, false, VaultLogFactory.class.getClassLoader());
            juliAvailable = true;
        } catch (Throwable ignored) {
            // JULI not present on classpath
        }
        HAS_TOMCAT_JULI = juliAvailable;

        // Auto-configure file logging if system property is set
        autoConfigureFileLogging();
    }

    private VaultLogFactory() {
        // Prevent instantiation
    }

    public static VaultLog getLog(Class<?> clazz) {
        return getLog(clazz != null ? clazz.getName() : "org.apache.tomcat.vault");
    }

    public static VaultLog getLog(String name) {
        String logName = (name != null && !name.trim().isEmpty()) ? name.trim() : "org.apache.tomcat.vault";
        if (HAS_TOMCAT_JULI) {
            try {
                Class<?> factoryClass = Class.forName(JULI_LOG_FACTORY);
                Method getLogMethod = factoryClass.getMethod("getLog", String.class);
                Object juliLog = getLogMethod.invoke(null, logName);
                if (juliLog != null) {
                    return new JuliVaultLog(logName, juliLog);
                }
            } catch (Throwable ignored) {
                // Fall back to JUL if reflection fails
            }
        }
        return new JulVaultLog(logName, Logger.getLogger(logName));
    }

    /**
     * Initializes file logging to a dedicated file for debugging.
     *
     * @param logPath path to log file (supports ${catalina.base} or ${catalina.home})
     * @param debug true to enable verbose FINE/DEBUG logging
     */
    public static synchronized void initFileLogging(String logPath, boolean debug) {
        if (logPath == null || logPath.trim().isEmpty()) {
            return;
        }

        String resolvedPath = resolvePathVariables(logPath.trim());
        File resolvedFile = new File(resolvedPath);
        File parent = resolvedFile.getParentFile();
        if (parent != null && !parent.exists()) {
            if (!parent.mkdirs() && !parent.exists()) {
                System.err.println("Warning: Unable to create log directory: " + parent.getAbsolutePath());
            }
        }

        try {
            FileHandler fileHandler;
            if (resolvedPath.contains("%g")) {
                fileHandler = new FileHandler(resolvedPath, 10 * 1024 * 1024, 5, true);
            } else {
                fileHandler = new FileHandler(resolvedPath, true);
            }

            fileHandler.setEncoding("UTF-8");
            Level level = debug ? Level.ALL : Level.INFO;
            fileHandler.setLevel(level);
            fileHandler.setFormatter(new Formatter() {
                private final SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");

                @Override
                public synchronized String format(LogRecord record) {
                    String date = dateFormat.format(new Date(record.getMillis()));
                    String thrown = "";
                    if (record.getThrown() != null) {
                        java.io.StringWriter sw = new java.io.StringWriter();
                        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
                        record.getThrown().printStackTrace(pw);
                        thrown = "\n" + sw;
                    }
                    return String.format("%s [%-5s] [%s] %s: %s%s\n",
                            date,
                            record.getLevel(),
                            Thread.currentThread().getName(),
                            record.getLoggerName(),
                            formatMessage(record),
                            thrown);
                }
            });

            Logger rootLogger = Logger.getLogger("org.apache.tomcat.vault");
            rootLogger.addHandler(fileHandler);
            if (debug) {
                rootLogger.setLevel(Level.ALL);
            }
            activeFileHandler = fileHandler;
            ACTIVE_HANDLERS.add(fileHandler);
            fileLoggingInitialized = true;

        } catch (IOException e) {
            System.err.println("Failed to initialize Tomcat Vault debug file logger: " + e.getMessage());
        }
    }

    /**
     * Closes and removes all active debug file handlers.
     */
    public static synchronized void closeFileHandlers() {
        if (activeFileHandler != null) {
            try {
                activeFileHandler.flush();
                activeFileHandler.close();
            } catch (Exception ignored) {
            }
            activeFileHandler = null;
        }
        Logger rootLogger = Logger.getLogger("org.apache.tomcat.vault");
        for (Handler handler : ACTIVE_HANDLERS) {
            try {
                rootLogger.removeHandler(handler);
                handler.flush();
                handler.close();
            } catch (Exception ignored) {
            }
        }
        ACTIVE_HANDLERS.clear();
        fileLoggingInitialized = false;
    }

    public static boolean isFileLoggingActive() {
        return fileLoggingInitialized;
    }

    public static boolean isTomcatJuliAvailable() {
        return HAS_TOMCAT_JULI;
    }

    static void publishToFile(String loggerName, Level level, String msg, Throwable thrown) {
        Handler h = activeFileHandler;
        if (h != null) {
            LogRecord lr = new LogRecord(level, msg);
            lr.setLoggerName(loggerName);
            lr.setThrown(thrown);
            h.publish(lr);
            h.flush();
        }
    }

    private static void autoConfigureFileLogging() {
        String logFile = System.getProperty(VaultConstants.SYS_PROP_LOG_FILE);
        if (logFile == null || logFile.trim().isEmpty()) {
            logFile = System.getenv(VaultConstants.ENV_LOG_FILE);
        }

        boolean debug = Boolean.getBoolean(VaultConstants.SYS_PROP_LOG_DEBUG);
        if (logFile != null && !logFile.trim().isEmpty()) {
            initFileLogging(logFile, debug);
        } else if (debug) {
            String catalinaBase = System.getProperty("catalina.base", System.getProperty("catalina.home", ""));
            if (!catalinaBase.isEmpty()) {
                initFileLogging(catalinaBase + "/logs/tomcat-vault-debug.log", true);
            }
        }
    }

    private static String resolvePathVariables(String path) {
        String base = System.getProperty("catalina.base", System.getProperty("catalina.home", "."));
        String home = System.getProperty("catalina.home", base);
        return path.replace("${catalina.base}", base)
                .replace("${catalina.home}", home);
    }

    /**
     * Adapter for org.apache.juli.logging.Log via reflection to avoid hard dependency at runtime.
     */
    public static class JuliVaultLog implements VaultLog {
        private final String name;
        private final Object target;
        private final Method debugMethod;
        private final Method debugExMethod;
        private final Method infoMethod;
        private final Method warnMethod;
        private final Method warnExMethod;
        private final Method errorMethod;
        private final Method errorExMethod;
        private final Method isDebugEnabledMethod;
        private final Method isInfoEnabledMethod;

        JuliVaultLog(String name, Object target) {
            this.name = name;
            this.target = target;
            Class<?> clazz = target.getClass();
            this.debugMethod = getMethod(clazz, "debug", Object.class);
            this.debugExMethod = getMethod(clazz, "debug", Object.class, Throwable.class);
            this.infoMethod = getMethod(clazz, "info", Object.class);
            this.warnMethod = getMethod(clazz, "warn", Object.class);
            this.warnExMethod = getMethod(clazz, "warn", Object.class, Throwable.class);
            this.errorMethod = getMethod(clazz, "error", Object.class);
            this.errorExMethod = getMethod(clazz, "error", Object.class, Throwable.class);
            this.isDebugEnabledMethod = getMethod(clazz, "isDebugEnabled");
            this.isInfoEnabledMethod = getMethod(clazz, "isInfoEnabled");
        }

        private static Method getMethod(Class<?> c, String name, Class<?>... params) {
            try {
                return c.getMethod(name, params);
            } catch (Exception e) {
                return null;
            }
        }

        private void invoke(Method m, Object... args) {
            if (m != null) {
                try {
                    m.invoke(target, args);
                } catch (Exception ignored) {
                }
            }
        }

        private boolean invokeBool(Method m) {
            if (m != null) {
                try {
                    Object res = m.invoke(target);
                    return res instanceof Boolean && (Boolean) res;
                } catch (Exception ignored) {
                }
            }
            return false;
        }

        @Override public boolean isDebugEnabled() { return invokeBool(isDebugEnabledMethod); }
        @Override public boolean isInfoEnabled() { return invokeBool(isInfoEnabledMethod); }
        @Override public void debug(String message) { invoke(debugMethod, message); publishToFile(name, Level.FINE, message, null); }
        @Override public void debug(String message, Throwable throwable) { invoke(debugExMethod, message, throwable); publishToFile(name, Level.FINE, message, throwable); }
        @Override public void info(String message) { invoke(infoMethod, message); publishToFile(name, Level.INFO, message, null); }
        @Override public void warn(String message) { invoke(warnMethod, message); publishToFile(name, Level.WARNING, message, null); }
        @Override public void warn(String message, Throwable throwable) { invoke(warnExMethod, message, throwable); publishToFile(name, Level.WARNING, message, throwable); }
        @Override public void error(String message) { invoke(errorMethod, message); publishToFile(name, Level.SEVERE, message, null); }
        @Override public void error(String message, Throwable throwable) { invoke(errorExMethod, message, throwable); publishToFile(name, Level.SEVERE, message, throwable); }
    }

    /**
     * Standard Java Util Logging adapter.
     */
    public static class JulVaultLog implements VaultLog {
        private final String name;
        private final Logger logger;

        public JulVaultLog(String name, Logger logger) {
            this.name = name;
            this.logger = logger;
        }

        @Override public boolean isDebugEnabled() { return logger.isLoggable(Level.FINE); }
        @Override public boolean isInfoEnabled() { return logger.isLoggable(Level.INFO); }
        @Override public void debug(String message) { logger.log(Level.FINE, message); publishToFile(name, Level.FINE, message, null); }
        @Override public void debug(String message, Throwable throwable) { logger.log(Level.FINE, message, throwable); publishToFile(name, Level.FINE, message, throwable); }
        @Override public void info(String message) { logger.log(Level.INFO, message); publishToFile(name, Level.INFO, message, null); }
        @Override public void warn(String message) { logger.log(Level.WARNING, message); publishToFile(name, Level.WARNING, message, null); }
        @Override public void warn(String message, Throwable throwable) { logger.log(Level.WARNING, message, throwable); publishToFile(name, Level.WARNING, message, throwable); }
        @Override public void error(String message) { logger.log(Level.SEVERE, message); publishToFile(name, Level.SEVERE, message, null); }
        @Override public void error(String message, Throwable throwable) { logger.log(Level.SEVERE, message, throwable); publishToFile(name, Level.SEVERE, message, throwable); }
    }
}
