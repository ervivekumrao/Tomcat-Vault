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

/**
 * Unified logging interface for Tomcat Vault.
 * Adapts transparently between Apache Tomcat JULI ({@code org.apache.juli.logging.Log})
 * when running inside a Tomcat container, and standard {@link java.util.logging.Logger}
 * when running standalone in CLI or automation tools.
 */
@SuppressWarnings("unused")
public interface VaultLog {

    boolean isDebugEnabled();

    boolean isInfoEnabled();

    void debug(String message);

    void debug(String message, Throwable throwable);

    void info(String message);

    void warn(String message);

    void warn(String message, Throwable throwable);

    void error(String message);

    void error(String message, Throwable throwable);
}
