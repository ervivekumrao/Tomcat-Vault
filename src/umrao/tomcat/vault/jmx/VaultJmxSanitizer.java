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

package umrao.tomcat.vault.jmx;

import umrao.tomcat.vault.ReferencePropertyDecryptor;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JMX Credential Sanitizer and Masking utility.
 * Prevents sensitive database passwords, keys, and tokens from being exposed
 * in cleartext when Tomcat connection pools are queried via JMX MBeans
 * (e.g., JConsole, VisualVM, or Prometheus JMX Exporter).
 * @author Vivek Umrao
 */
@SuppressWarnings("unused")
public final class VaultJmxSanitizer {

    public static final String MASK = "******";
    private static final Pattern URL_CREDENTIAL_PATTERN = Pattern.compile("(?i)(:[^:@/?;#]+)@");
    private static final Pattern ORACLE_THIN_PATTERN = Pattern.compile("(?i)(:[a-zA-Z0-9_.-]+)/([^:@/?;#]+)@");
    private static final Pattern ORACLE_TNS_PASSWORD_PATTERN = Pattern.compile("(?i)\\(PASSWORD\\s*=\\s*[^)]+\\)");
    private static final Pattern PARAM_CREDENTIAL_PATTERN = Pattern.compile("(?i)(password|pwd|secret|token|apikey|credential)\\s*=\\s*([^&;\\s)]+)");

    private VaultJmxSanitizer() {
        // Prevent instantiation
    }

    /**
     * Sanitizes a single attribute value based on the property name.
     *
     * @param attributeName name of attribute (e.g. "password", "url", "user")
     * @param rawValue the raw property value
     * @return masked value if sensitive, or original value if benign
     */
    public static Object sanitizeAttribute(String attributeName, Object rawValue) {
        if (rawValue == null) {
            return null;
        }

        if (ReferencePropertyDecryptor.isSensitive(attributeName)) {
            String strVal = rawValue.toString();
            // If it's a URL, mask embedded credentials
            if (attributeName.toLowerCase().contains("url")) {
                return sanitizeUrl(strVal);
            }
            return MASK;
        }

        return rawValue;
    }

    /**
     * Sanitizes all attributes in a property or MBean map.
     *
     * @param attributes attribute map
     * @return new map with all sensitive fields masked
     */
    public static Map<String, Object> sanitizeAttributes(Map<String, Object> attributes) {
        if (attributes == null || attributes.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, Object> sanitized = new HashMap<>(attributes.size());
        for (Map.Entry<String, Object> entry : attributes.entrySet()) {
            sanitized.put(entry.getKey(), sanitizeAttribute(entry.getKey(), entry.getValue()));
        }
        return sanitized;
    }

    /**
     * Masks any password or sensitive credential embedded inside a JDBC connection URL.
     * Supports standard user:pass@host, Oracle thin scott/tiger@host, Oracle TNS (PASSWORD=...),
     * and query/connection parameters (password=..., pwd=..., etc.).
     *
     * @param url candidate JDBC URL
     * @return sanitized URL
     */
    public static String sanitizeUrl(String url) {
        if (url == null || url.isEmpty()) {
            return url;
        }
        if (url.indexOf('@') == -1 && url.indexOf('=') == -1) {
            return url;
        }
        String sanitized = url;
        Matcher m1 = URL_CREDENTIAL_PATTERN.matcher(sanitized);
        if (m1.find()) {
            sanitized = m1.replaceAll(":******@");
        }
        Matcher m2 = ORACLE_THIN_PATTERN.matcher(sanitized);
        if (m2.find()) {
            sanitized = m2.replaceAll("$1/******@");
        }
        Matcher m3 = ORACLE_TNS_PASSWORD_PATTERN.matcher(sanitized);
        if (m3.find()) {
            sanitized = m3.replaceAll("(PASSWORD=******)");
        }
        Matcher m4 = PARAM_CREDENTIAL_PATTERN.matcher(sanitized);
        if (m4.find()) {
            sanitized = m4.replaceAll("$1=******");
        }
        return sanitized;
    }
}
