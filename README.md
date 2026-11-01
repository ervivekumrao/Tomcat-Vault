# Tomcat Vault (`tomcat-vault`)

[![Java](https://img.shields.io/badge/Java-8%20--%2025%2B-blue.svg)](https://openjdk.org/)
[![Tomcat](https://img.shields.io/badge/Apache%20Tomcat-7%20--%2011-orange.svg)](https://tomcat.apache.org/)
[![Security](https://img.shields.io/badge/Crypto-AES--256--GCM-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-135%20passed-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/Coverage-93.0%25%20instruction%20|%20100%25%20class-success.svg)]()

Enterprise-grade cryptographic credential manager, diagnostic verifier, and JNDI DataSource factory for Apache Tomcat connection pools. Eliminates cleartext database credentials from `context.xml` and `server.xml` using authenticated encryption (AES-256-GCM), dynamic initialization vectors, pluggable key providers, cloud vault connectors, zero-downtime key rotation, and zero-leak logging.

---

## Table of Contents
- [Key Features](#key-features)
- [Architecture & Flow](#architecture--flow)
- [Quick Start: CLI Usage](#quick-start-cli-usage)
  - [1. Build the JAR](#1-build-the-jar)
  - [2. Generate Master Cryptographic Keys](#2-generate-master-cryptographic-keys)
  - [3. Encrypt Credentials](#3-encrypt-credentials)
  - [4. Decrypt Credentials](#4-decrypt-credentials)
  - [5. Verify DataSources (Dry-Run Connectivity Check)](#5-verify-datasources-dry-run-connectivity-check)
  - [6. System Health & Diagnostics](#6-system-health--diagnostics)
  - [7. In-Place Re-Encryption & Key Migration](#7-in-place-re-encryption--key-migration)
  - [8. Masking & Benchmarking](#8-masking--benchmarking)
- [Tomcat Setup & Configuration](#tomcat-setup--configuration)
  - [1. Deploy the JAR](#1-deploy-the-jar)
  - [2. Key Provider Configuration](#2-key-provider-configuration)
  - [3. DataSource Configuration in context.xml](#3-datasource-configuration-in-contextxml)
    - [A. HikariCP Connection Pool](#a-hikaricp-connection-pool-recommended-for-performance)
    - [B. Tomcat DBCP2 Pool](#b-tomcat-dbcp2-pool)
    - [C. Tomcat JDBC Connection Pool](#c-tomcat-jdbc-connection-pool)
    - [D. Universal / Generic Connection Pool (Vibur, C3P0)](#d-universal--generic-connection-pool-vibur-c3p0)
    - [E. Cloud Secret Connectors (Zero Static Keys)](#e-cloud-secret-connectors-zero-static-keys)
- [Operational Hardening & Performance](#operational-hardening--performance)
- [Key Resolution Hierarchy](#key-resolution-hierarchy)
- [Automated Testing & Quality Assurance](#automated-testing--quality-assurance)
- [License & Developer Info](#license--developer-info)

---

## Key Features

- **Modern Authenticated Encryption (AES-256-GCM):**
  Uses 256-bit AES in Galois/Counter Mode (GCM) with a 12-byte cryptographically secure random IV generated per encryption and 128-bit authentication tag. Protects against chosen-ciphertext and padding oracle attacks.
- **Envelope Standard (`ENC(...)`):**
  Adopts the industry standard `ENC(Base64(IV + Ciphertext + Tag))` envelope convention (compatible with Jasypt, Spring Cloud Config, and enterprise secret injectors).
- **100% Backward Compatible:**
  Seamlessly decodes legacy ciphertexts (hex-encoded CBC with `@##$$$&&&&` marker) without requiring existing production configurations to be re-encrypted immediately.
- **Connection Verification & Dry-Run CLI:**
  Validate credentials and test live database connections against `context.xml` before restarting Tomcat (`tomcat-vault.jar --verify --context ...`).
- **Multi-Key & Key Versioning Architecture:**
  Support for zero-downtime key rotation via tagged envelopes (`ENC(v1:...)`, `ENC(v2:...)`, `ENC(key-alias=...)`).
- **Universal Connection Pool Support:**
  - **HikariCP Pool:** [`VaultHikariDataSourceFactory`](src/umrao/tomcat/vault/VaultHikariDataSourceFactory.java)
  - **Tomcat DBCP2 Pool:** [`VaultBasicDataSourceFactory`](src/umrao/tomcat/vault/VaultBasicDataSourceFactory.java)
  - **Tomcat JDBC Pool:** [`VaultDataSourceFactory`](src/umrao/tomcat/vault/VaultDataSourceFactory.java)
  - **Universal Pool Adapter:** [`VaultGenericDataSourceFactory`](src/umrao/tomcat/vault/VaultGenericDataSourceFactory.java) (for Vibur DBCP, C3P0, BoneCP)
- **PKCS#12 & Java KeyStore Integration:**
  Hardware Security Module (HSM) and KeyStore provider ([`KeyStoreKeyProvider`](src/umrao/tomcat/vault/key/KeyStoreKeyProvider.java)) supporting PKCS#12 and JKS files compliant with FIPS 140-2 and PCI-DSS.
- **Cloud & Enterprise Secret Connectors:**
  Direct resolution for AWS Secrets Manager (`AWS_SECRET(...)`), HashiCorp Vault (`VAULT(...)`), Azure Key Vault (`AZURE_VAULT(...)`), and GCP Secret Manager (`GCP_SECRET(...)`) with in-memory TTL caching.
- **Master Key Cloud Provider ([`SecretResolverKeyProvider`](src/umrao/tomcat/vault/key/SecretResolverKeyProvider.java)):**
  Enables the master cryptographic key itself to be fetched dynamically from AWS Secrets Manager or HashiCorp Vault (`-Dtomcat.vault.cloud.path=...`).
- **Dynamic Credential Refresh Coordinator:**
  [`VaultCredentialReloader`](src/umrao/tomcat/vault/refresh/VaultCredentialReloader.java) evicts stale connections and re-authenticates connection pools upon credential rotation without bouncing Tomcat.
- **JMX MBean Credential Masking:**
  [`VaultJmxSanitizer`](src/umrao/tomcat/vault/jmx/VaultJmxSanitizer.java) automatically masks passwords and embedded URL credentials with `******` in JMX trees (JConsole, VisualVM, Prometheus).
- **Kubernetes Secret File Auto-Reload:**
  [`FileKeyProvider`](src/umrao/tomcat/vault/key/FileKeyProvider.java) automatically detects file timestamp/size changes on disk and reloads updated Kubernetes Secret mounts dynamically.
- **SIEM Structured JSON Audit Logging:**
  [`VaultAuditLogger`](src/umrao/tomcat/vault/audit/VaultAuditLogger.java) emits tamper-evident structured audit events for security operations without logging plaintext credentials.

---

## Architecture & Flow

```mermaid
flowchart LR
    subgraph Config["Configuration"]
        XML["context.xml / server.xml<br/>password='ENC(...)'<br/>url='jdbc:...AWS_SECRET(...)'"]
    end

    subgraph Factory["Tomcat Vault JNDI Factory"]
        VDS["VaultHikariDataSourceFactory<br/>VaultBasicDataSourceFactory<br/>VaultDataSourceFactory"]
        DEC["ReferencePropertyDecryptor"]
    end

    subgraph Crypto["Cryptographic Engine"]
        VC["VaultCrypto (AES-256-GCM)"]
        LRU["Bounded LRU Key Cache"]
        REG["SecretResolverRegistry<br/>(TTL Cached)"]
    end

    subgraph Keys["Key Resolution Hierarchy"]
        P1["1. System Property"]
        P2["2. Environment Variable"]
        P3["3. Cloud Vault Key Provider"]
        P4["4. Kubernetes Key File"]
        P5["5. Java KeyStore / HSM"]
    end

    subgraph Target["Live Connection Pool"]
        POOL["HikariCP / Tomcat JDBC / DBCP2"]
        JMX["JMX MBean Credential Masking"]
    end

    XML --> VDS
    VDS --> DEC
    DEC --> VC
    DEC --> REG
    VC --> LRU
    VC --> Keys
    DEC --> POOL
    POOL --> JMX
```

---

## Quick Start: CLI Usage

### 1. Build the JAR

Using the Gradle Wrapper (Linux / macOS / WSL):
```bash
./gradlew clean jar
```

On Windows (Command Prompt / PowerShell):
```cmd
gradlew.bat clean jar
```

The output executable JAR is generated at `build/libs/tomcat-vault-2.0.0.jar`.

---

### 2. Generate Master Cryptographic Keys

Generate high-entropy, 256-bit random master keys formatted as both Hex and Base64:
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar --generate-key
```

Sample output:
```text
Tomcat Vault - Cryptographic Key Generator
==========================================
Generated 256-bit Random AES Master Key:
------------------------------------------
HEX:    A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
BASE64: obLD1OX2eJASNFZ4mrze8BI0VniarN7wEjRWeJq83vA=
```

---

### 3. Encrypt Credentials

#### A. Interactive Masked Entry (Recommended for Security)
Avoids leaving passwords in shell history (`.bash_history`) or process listings (`ps aux`):
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar -e
```

Interactive prompt and generated ciphertext output:
```text
Enter secret to encrypt: [input hidden]
encrypted: ENC(axVXzR5w+rr8ICucjw/ZZzhila/psl0pwBez6wo+29k3+Hbi/+6kN/YFcaqhOoCxniLc)
```

#### B. Pipeline Streaming (Stdin)
```bash
echo -n "mySecretPassword" | java -jar build/libs/tomcat-vault-2.0.0.jar -e -
```

#### C. With External Key or Key Versioning
Encrypt with a custom key and version tag:
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar -e "mySecretPassword" -k "MasterKeySecret123" --key-alias v2
```

Sample output:
```text
encrypted: ENC(v2:5OQ5zb9OtEIDBkauX7eTWNPuG8sRjidwxyrAQDT4SOGXSlu6+IxIsQujw/522knW8EQiood5FZyT2bGM)
```

#### D. Using an External Key File
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar -e "mySecretPassword" --keyfile /etc/tomcat/vault.key
```

---

### 4. Decrypt Credentials
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar -d "ENC(axVXzR5w+rr8ICucjw/ZZzhila/psl0pwBez6wo+29k3+Hbi/+6kN/YFcaqhOoCxniLc)"
```

---

### 5. Verify DataSources (Dry-Run Connectivity Check)
Before restarting production Tomcat, verify that all encrypted credentials in your configuration file can be successfully decrypted and establish live database connections:

```bash
java -jar build/libs/tomcat-vault-2.0.0.jar -v -c /opt/tomcat/conf/context.xml
```

With custom key and debug log file:
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar -v -c /opt/tomcat/conf/context.xml -k "MasterKeySecret123" --debug-log /tmp/vault-verify.log
```

**Sample Output:**
```text
Tomcat Vault: Verifying DataSource configurations in /opt/tomcat/conf/context.xml...
--------------------------------------------------------------------------------
[✓] Resource 'jdbc/AppDB': Successfully decrypted credentials & established live JDBC connection (latency: 14ms).
[✓] Resource 'jdbc/ReadOnlyDB': Non-JDBC or URL not defined. Decryption verified.
--------------------------------------------------------------------------------
Verification Summary: 2/2 resources passed.
```

---

### 6. System Health & Diagnostics
Check the operational readiness of Tomcat Vault, JVM cryptography providers, unlimited strength JCE policy, and key provider resolution:
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar --status
```

Sample Output:
```text
Tomcat Vault - System & Cryptographic Diagnostics
=================================================
Java Runtime: OpenJDK Runtime Environment (21.0.2)
OS:           Linux 6.6.137+ (amd64)
JCE Policy:   [OK] Unlimited Strength Jurisdiction (Max AES: 2147483647-bit)
Cipher GCM:   [OK] AES/GCM/NoPadding available
KDF PBKDF2:   [OK] PBKDF2WithHmacSHA256 available (600,000 iterations)
Key Provider: [OK] Active Key Provider: SystemPropertyKeyProvider
Self-Test:    [OK] AES-256-GCM round-trip encrypt/decrypt verified successfully.
-------------------------------------------------
Diagnostic Result: ALL CHECKS PASSED
```

---

### 7. In-Place Re-Encryption & Key Migration
Rotate master keys across existing `context.xml` files automatically with automatic backup creation:
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar re-encrypt \
  -c /opt/tomcat/conf/context.xml \
  --old-key "OldPassphrase123" \
  --new-key "NewPassphrase456" \
  --new-alias v2
```

---

### 8. Masking & Benchmarking

**Mask JDBC URLs:**
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar --mask "jdbc:mysql://admin:secret123@db.prod:3306/appdb"
# Outputs: masked: jdbc:mysql://admin:******@db.prod:3306/appdb
```

**Run Cryptographic Engine Benchmark:**
```bash
java -jar build/libs/tomcat-vault-2.0.0.jar --benchmark
```

---

## Tomcat Setup & Configuration

### 1. Deploy the JAR
Copy `tomcat-vault-2.0.0.jar` to `$CATALINA_HOME/lib/` or `$CATALINA_BASE/lib/`:
```bash
cp build/libs/tomcat-vault-2.0.0.jar /opt/tomcat/lib/
```

---

### 2. Key Provider Configuration
Supply the master encryption key using any of the following methods in `$CATALINA_HOME/bin/setenv.sh`:

#### Option A: Environment Variable (Recommended for Docker / Kubernetes)
```bash
export TOMCAT_VAULT_KEY="MasterKeySecret123"
```

#### Option B: External Kubernetes Secret File Mount
```bash
CATALINA_OPTS="$CATALINA_OPTS -Dtomcat.vault.keyfile=/etc/secrets/vault.key"
```

#### Option C: Java KeyStore (PKCS#12 / HSM)
```bash
CATALINA_OPTS="$CATALINA_OPTS \
  -Dtomcat.vault.keystore=/etc/security/vault.p12 \
  -Dtomcat.vault.keystore.password=KeystorePass123 \
  -Dtomcat.vault.keystore.alias=tomcat-vault"
```

#### Option D: Cloud Secret Vault Connector
```bash
CATALINA_OPTS="$CATALINA_OPTS -Dtomcat.vault.cloud.path=AWS_SECRET(prod/tomcat#encryption_key)"
```

#### Option E: Strict Production Mode
Prevent accidental fallback to development keys:
```bash
CATALINA_OPTS="$CATALINA_OPTS -Dtomcat.vault.strict=true"
```

---

### 3. DataSource Configuration in `context.xml`

#### A. HikariCP Connection Pool (Recommended for Performance)
```xml
<Resource
    name="jdbc/AppDB"
    auth="Container"
    type="javax.sql.DataSource"
    factory="umrao.tomcat.vault.VaultHikariDataSourceFactory"
    driverClassName="com.mysql.cj.jdbc.Driver"
    jdbcUrl="jdbc:mysql://db.prod.internal:3306/appdb"
    username="app_user"
    password="ENC(axVXzR5w+rr8ICucjw/ZZzhila/psl0pwBez6wo+29k3+Hbi/+6kN/YFcaqhOoCxniLc)"
    maximumPoolSize="20"
    minimumIdle="5" />
```

#### B. Tomcat DBCP2 Pool
```xml
<Resource
    name="jdbc/LegacyDBCP"
    auth="Container"
    type="javax.sql.DataSource"
    factory="umrao.tomcat.vault.VaultBasicDataSourceFactory"
    driverClassName="org.postgresql.Driver"
    url="jdbc:postgresql://postgres.prod.internal:5432/appdb"
    username="db_user"
    password="ENC(axVXzR5w+rr8ICucjw/ZZzhila/psl0pwBez6wo+29k3+Hbi/+6kN/YFcaqhOoCxniLc)" />
```

#### C. Tomcat JDBC Connection Pool
```xml
<Resource
    name="jdbc/TomcatPool"
    auth="Container"
    type="javax.sql.DataSource"
    factory="umrao.tomcat.vault.VaultDataSourceFactory"
    driverClassName="com.microsoft.sqlserver.jdbc.SQLServerDriver"
    url="jdbc:sqlserver://sql.prod.internal:1433;databaseName=appdb"
    username="sql_user"
    password="ENC(v2:5OQ5zb9OtEIDBkauX7eTWNPuG8sRjidwxyrAQDT4SOGXSlu6+IxIsQujw/522knW8EQiood5FZyT2bGM)" />
```

#### D. Universal / Generic Connection Pool (Vibur, C3P0)
```xml
<Resource
    name="jdbc/GenericPool"
    auth="Container"
    type="javax.sql.DataSource"
    factory="umrao.tomcat.vault.VaultGenericDataSourceFactory"
    delegateFactory="org.vibur.dbcp.ViburDBCPObjectFactory"
    driverClassName="org.h2.Driver"
    jdbcUrl="jdbc:h2:mem:testdb"
    username="sa"
    password="ENC(axVXzR5w+rr8ICucjw/ZZzhila/psl0pwBez6wo+29k3+Hbi/+6kN/YFcaqhOoCxniLc)" />
```

#### E. Cloud Secret Connectors (Zero Static Keys)
Resolve credentials directly from cloud secret managers at connection pool startup:
```xml
<Resource
    name="jdbc/CloudDB"
    auth="Container"
    type="javax.sql.DataSource"
    factory="umrao.tomcat.vault.VaultDataSourceFactory"
    username="AWS_SECRET(prod/database#username)"
    password="AWS_SECRET(prod/database#password)"
    url="jdbc:mysql://db.prod.internal:3306/appdb" />
```
*(Supports `AWS_SECRET(name#field)`, `VAULT(path#field)`, `AZURE_VAULT(secret-name)`, and `GCP_SECRET(secret-name)`).*

---

## Operational Hardening & Performance

- **Bounded LRU Key Caching:**
  PBKDF2 key derivations are cached in a thread-safe, access-order LRU cache bounded to 128 keys, preventing memory expansion and redundant hashing overhead.
- **Cloud Secret TTL Caching:**
  Cloud secrets resolved via `SecretResolverRegistry` are cached with a configurable in-memory TTL (default: 5 minutes, configurable via `tomcat.vault.secret.cache.ttl.ms`), preventing cloud API rate limits and connection latency spikes.
- **Cached Reflection for Pool Purging:**
  [`VaultCredentialReloader`](src/umrao/tomcat/vault/refresh/VaultCredentialReloader.java) caches discovered connection pool eviction methods in a `ConcurrentHashMap`, avoiding reflection overhead and `NoSuchMethodException` stack trace allocations during credential rotation.
- **Fast URL Short-Circuit:**
  [`VaultJmxSanitizer`](src/umrao/tomcat/vault/jmx/VaultJmxSanitizer.java) short-circuits URLs that do not contain credential delimiters, delivering maximum throughput for JMX monitoring tools.

---

## Key Resolution Hierarchy

When resolving encryption keys at runtime, `tomcat-vault` evaluates providers in strict priority order:

```mermaid
flowchart TD
    Req["Decrypt Request<br/>(e.g. key-alias=v2)"] --> P1["1. Java System Property<br/>(-Dtomcat.vault.key or -Dtomcat.vault.key.v2)"]
    P1 -->|Not Found| P2["2. Environment Variable<br/>(TOMCAT_VAULT_KEY or TOMCAT_VAULT_KEY_V2)"]
    P2 -->|Not Found| P3["3. Cloud Vault Key Provider<br/>(-Dtomcat.vault.cloud.path)"]
    P3 -->|Not Found| P4["4. Kubernetes Key File<br/>(-Dtomcat.vault.keyfile / K8s auto-reload)"]
    P4 -->|Not Found| P5["5. Java KeyStore / HSM<br/>(-Dtomcat.vault.keystore PKCS#12)"]
    P5 -->|Not Found| Dev["6. Dev Default Key<br/>(Strict Mode: throws SecurityException)"]
```

---

## Automated Testing & Quality Assurance

Run the test suite and generate HTML/CSV coverage reports:

```bash
./gradlew test jacocoTestReport
```

### Metrics:
- **Test Results:** 135 / 135 passed (0 failures, 0 errors)
- **Class Coverage:** 100% (39 / 39 classes covered)
- **Instruction Coverage:** 93.0%
- **Line Coverage:** 92.9%
- **Method Coverage:** 98.9%

### Stress, Chaos & Concurrency Test Highlights:
- **`LiveProductionChaosAndUnstableEnvironmentTest`:**
  - Multi-process stampede executing the actual generated `tomcat-vault-2.0.0.jar` across concurrent JVM processes.
  - Connection pool resilience & auto-recovery during database disconnects and transient SQL drops.
  - Intermittent cloud vault provider outages (503 Service Unavailable / timeouts) shielded by in-memory TTL cache with zero request loss.
  - Dynamic key rotation stampede combined with corrupted / tampered ciphertext injection under load.
  - Memory pressure & GC stability under sustained allocation churn.
- **`VaultHighConcurrencyStressAndLoadTest`:**
  - 50 concurrent worker threads executing 50,000+ encryption/decryption operations.
  - Zero-downtime key rotation under concurrent read/write stampede.
  - Cloud secret resolution stampede with TTL cache verification.
  - High-frequency JMX URL sanitization stress.
- **`RealtimeConcurrencyAndDistributedLoadTest`:**
  - Multi-process distributed cluster simulation with isolated JVM processes.
  - Live H2 database connection checkout and execution under 50-worker distributed load.

---

## License & Developer Info

- **License:** [Apache License, Version 2.0](LICENSE)
- **Author & Developer:** Vivek Umrao
- **Copyright:** Copyright 2024-2026 the original author or authors (Vivek Umrao).
