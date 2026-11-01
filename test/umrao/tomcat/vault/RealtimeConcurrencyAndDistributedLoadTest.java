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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import umrao.tomcat.vault.audit.VaultAuditLogger;
import umrao.tomcat.vault.jmx.VaultStatus;
import umrao.tomcat.vault.key.CompositeKeyProvider;
import umrao.tomcat.vault.key.KeyProvider;
import umrao.tomcat.vault.refresh.VaultCredentialReloader;
import umrao.tomcat.vault.secret.SecretResolver;
import umrao.tomcat.vault.secret.SecretResolverRegistry;

import javax.naming.Reference;
import javax.naming.StringRefAddr;
import javax.sql.DataSource;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings({"resource", "SqlNoDataSourceInspection", "SqlResolve"})
public class RealtimeConcurrencyAndDistributedLoadTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
        System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        VaultStatus.unregisterMBean();
        VaultCredentialReloader.getInstance().clearListeners();
        VaultAuditLogger.getInstance().setEventConsumer(null);
    }

    @Test
    @DisplayName("Realtime Scenario 1: High concurrency decryption throughput under stampede load")
    void testHighConcurrencyDecryptionThroughput() throws Exception {
        int threadCount = 32;
        int operationsPerThread = 150;
        int totalOperations = threadCount * operationsPerThread;

        VaultCrypto crypto = new VaultCrypto("ProdHighThroughputMasterKey2026!");
        String[] secrets = new String[]{
                "DB_SuperSecretPassword_#1",
                "OAuth_Client_Secret_XYZ_987654321",
                "API_Key_Prod_Cluster_abcdef0123456789",
                "JWT_Signing_Key_Token_32_bytes_long!",
                "P@$$w0rd_With_Spec!al_Ch@rs_#%*()_+~"
        };
        String[] ciphertexts = new String[secrets.length];
        for (int i = 0; i < secrets.length; i++) {
            ciphertexts[i] = crypto.encrypt(secrets[i]);
        }

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(threadCount);

        LongAdder successCount = new LongAdder();
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
        long startTime = System.nanoTime();

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int i = 0; i < operationsPerThread; i++) {
                        int index = (threadId + i) % secrets.length;
                        String decrypted = crypto.decrypt(ciphertexts[index]);
                        if (secrets[index].equals(decrypted)) {
                            successCount.increment();
                        } else {
                            errors.add(new AssertionError("Decryption mismatch on thread " + threadId));
                        }
                    }
                } catch (Throwable e) {
                    errors.add(e);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = endGate.await(15, TimeUnit.SECONDS);
        long elapsedMs = (System.nanoTime() - startTime) / 1_000_000;
        executor.shutdown();

        assertTrue(completed, "High concurrency decryption timed out");
        assertTrue(errors.isEmpty(), "Encountered concurrency errors: " + errors);
        assertEquals(totalOperations, successCount.sum(), "All operations should succeed");

        double opsPerSec = (totalOperations * 1000.0) / elapsedMs;
        System.out.printf("[Realtime Concurrency Benchmark] Decryptions: %d ops | Concurrency: %d threads | Time: %d ms | Throughput: %.0f ops/sec%n",
                totalOperations, threadCount, elapsedMs, opsPerSec);
    }

    @Test
    @DisplayName("Realtime Scenario 2: Zero-downtime key rotation under concurrent read load")
    void testZeroDowntimeKeyRotationUnderConcurrentLoad() throws Exception {
        int readerThreads = 20;
        int operationsPerReader = 100;

        CompositeKeyProvider compositeKeyProvider = new CompositeKeyProvider();
        String oldKey = "OldClusterKey1234567890123456789";
        String newKey = "NewClusterKey9876543210987654321";

        compositeKeyProvider.addProvider(new KeyProvider() {
            @Override public String getKey() { return oldKey; }
            @Override public String getKey(String alias) { return "v1".equals(alias) ? oldKey : null; }
            @Override public boolean hasKey(String alias) { return "v1".equals(alias) || alias == null; }
            @Override public String getProviderName() { return "V1KeyProvider"; }
        });

        VaultCrypto cryptoV1 = new VaultCrypto(compositeKeyProvider);
        String v1Ciphertext = cryptoV1.encrypt("ZeroDowntimePayload", "v1", null);

        VaultCrypto dynamicCrypto = new VaultCrypto(compositeKeyProvider);

        ExecutorService readerExecutor = Executors.newFixedThreadPool(readerThreads);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch finishGate = new CountDownLatch(readerThreads);

        AtomicBoolean rotatorDone = new AtomicBoolean(false);
        LongAdder successfulReads = new LongAdder();
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < readerThreads; i++) {
            readerExecutor.submit(() -> {
                try {
                    startGate.await();
                    for (int op = 0; op < operationsPerReader; op++) {
                        String decrypted = dynamicCrypto.decrypt(v1Ciphertext);
                        if ("ZeroDowntimePayload".equals(decrypted)) {
                            successfulReads.increment();
                        } else {
                            errors.add(new AssertionError("Data mismatch during key rotation"));
                        }
                        Thread.yield();
                    }
                } catch (Throwable t) {
                    errors.add(t);
                } finally {
                    finishGate.countDown();
                }
            });
        }

        startGate.countDown();

        // In-flight rotation by adding v2 key provider dynamically
        compositeKeyProvider.addProvider(new KeyProvider() {
            @Override public String getKey() { return newKey; }
            @Override public String getKey(String alias) { return "v2".equals(alias) ? newKey : null; }
            @Override public boolean hasKey(String alias) { return "v2".equals(alias); }
            @Override public String getProviderName() { return "V2KeyProvider"; }
        });
        rotatorDone.set(true);

        // Encrypt with v2 while readers are still active
        String v2Ciphertext = dynamicCrypto.encrypt("NewPayloadUnderV2", "v2", null);
        assertEquals("NewPayloadUnderV2", dynamicCrypto.decrypt(v2Ciphertext));

        boolean completed = finishGate.await(10, TimeUnit.SECONDS);
        readerExecutor.shutdown();

        assertTrue(rotatorDone.get(), "Key rotator should be marked done");
        assertTrue(completed, "Readers did not complete in time");
        assertTrue(errors.isEmpty(), "Errors during concurrent rotation: " + errors);
        assertEquals(readerThreads * operationsPerReader, successfulReads.sum());
    }

    @Test
    @DisplayName("Realtime Scenario 3: Concurrent DataSource factory creation and live H2 connections")
    void testConcurrentDataSourceFactoryWithLiveH2() throws Exception {
        int poolThreads = 16;
        VaultCrypto crypto = new VaultCrypto("DataSourcePoolTestKey123456789012");
        String encPass = crypto.encrypt("h2secret");
        String encUser = crypto.encrypt("sa");

        ExecutorService executor = Executors.newFixedThreadPool(poolThreads);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(poolThreads);

        AtomicInteger successfulConnections = new AtomicInteger(0);
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < poolThreads; i++) {
            final int id = i;
            executor.submit(() -> {
                try {
                    startGate.await();

                    Reference ref = new Reference("javax.sql.DataSource");
                    ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
                    ref.add(new StringRefAddr("jdbcUrl", "jdbc:h2:mem:concurrent_db_" + id + ";DB_CLOSE_DELAY=-1"));
                    ref.add(new StringRefAddr("username", encUser));
                    ref.add(new StringRefAddr("password", encPass));

                    VaultHikariDataSourceFactory factory = new VaultHikariDataSourceFactory(new ReferencePropertyDecryptor(crypto));
                    Object obj = factory.getObjectInstance(ref, null, null, new Hashtable<>());
                    assertNotNull(obj);
                    assertInstanceOf(DataSource.class, obj);

                    DataSource ds = (DataSource) obj;
                    try (Connection conn = ds.getConnection();
                         Statement stmt = conn.createStatement()) {
                        stmt.execute("CREATE TABLE test_data (id INT PRIMARY KEY, name VARCHAR(50))");
                        stmt.execute("INSERT INTO test_data VALUES (1, 'TomcatVaultConcurrent')");
                        try (ResultSet rs = stmt.executeQuery("SELECT name FROM test_data WHERE id = 1")) {
                            if (rs.next() && "TomcatVaultConcurrent".equals(rs.getString(1))) {
                                successfulConnections.incrementAndGet();
                            }
                        }
                    }

                    if (obj instanceof AutoCloseable) {
                        ((AutoCloseable) obj).close();
                    }
                } catch (Throwable e) {
                    errors.add(e);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = endGate.await(15, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "Connection pool creation timed out");
        assertTrue(errors.isEmpty(), "Encountered connection pool errors: " + errors);
        assertEquals(poolThreads, successfulConnections.get(), "All threads should successfully query the database");
    }

    @Test
    @DisplayName("Realtime Scenario 4: Concurrent credential reload and pool connection eviction stampede")
    void testConcurrentCredentialReloadStampede() throws Exception {
        VaultCredentialReloader reloader = VaultCredentialReloader.getInstance();
        reloader.clearListeners();

        int pools = 20;
        AtomicInteger totalEvictions = new AtomicInteger(0);

        for (int i = 0; i < pools; i++) {
            final int poolId = i;
            reloader.addListener(resource -> {
                if (("jdbc/Pool" + poolId).equals(resource) || "*".equals(resource)) {
                    totalEvictions.incrementAndGet();
                }
            });
        }

        assertEquals(pools, reloader.getListenerCount());

        int broadcastThreads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(broadcastThreads);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(broadcastThreads);

        for (int t = 0; t < broadcastThreads; t++) {
            executor.submit(() -> {
                try {
                    startGate.await();
                    reloader.notifyReload("*");
                } catch (Exception e) {
                    fail(e);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = endGate.await(10, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed);
        assertEquals(broadcastThreads * pools, totalEvictions.get(), "Each wildcard reload should trigger all registered pool listeners");
    }

    @Test
    @DisplayName("Realtime Scenario 5: High concurrency distributed cloud secret resolution")
    void testConcurrentDistributedSecretResolution() throws Exception {
        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();
        int resolutionThreads = 24;
        int iterations = 100;

        for (int i = 0; i < 5; i++) {
            System.setProperty("cloud.secret.db.user" + i, "ResolvedCloudUser" + i);
        }

        SecretResolver customCloudResolver = new SecretResolver() {
            @Override public boolean supports(String expr) { return expr != null && expr.startsWith("CLOUD_STORE("); }
            @Override public String resolve(String expr) {
                String key = expr.substring("CLOUD_STORE(".length(), expr.length() - 1);
                return "MockDistributedSecret:" + System.getProperty(key, "default");
            }
            @Override public String getResolverName() { return "MockCloudStoreResolver"; }
        };

        registry.registerResolver(customCloudResolver);

        ExecutorService executor = Executors.newFixedThreadPool(resolutionThreads);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(resolutionThreads);

        LongAdder successResolutions = new LongAdder();
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());

        for (int t = 0; t < resolutionThreads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int i = 0; i < iterations; i++) {
                        int secretIdx = (threadId + i) % 5;
                        String expr = "CLOUD_STORE(cloud.secret.db.user" + secretIdx + ")";
                        String resolved = registry.resolve(expr);
                        if (("MockDistributedSecret:ResolvedCloudUser" + secretIdx).equals(resolved)) {
                            successResolutions.increment();
                        } else {
                            errors.add(new AssertionError("Cloud secret resolution mismatch: " + resolved));
                        }
                    }
                } catch (Throwable t1) {
                    errors.add(t1);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = endGate.await(10, TimeUnit.SECONDS);
        executor.shutdown();
        registry.unregisterResolver(customCloudResolver);

        assertTrue(completed);
        assertTrue(errors.isEmpty(), "Errors during concurrent cloud secret resolution: " + errors);
        assertEquals(resolutionThreads * iterations, successResolutions.sum());
    }

    @Test
    @DisplayName("Realtime Scenario 6: High-frequency concurrent SIEM audit logging without drop or corruption")
    void testConcurrentSIEMAuditLoggingThroughput() throws Exception {
        VaultAuditLogger auditLogger = VaultAuditLogger.getInstance();
        int loggerThreads = 16;
        int eventsPerThread = 200;
        int totalExpectedEvents = loggerThreads * eventsPerThread;

        LongAdder loggedEvents = new LongAdder();
        auditLogger.setEventConsumer(json -> {
            if (json.contains("\"event\":\"CONCURRENT_TEST\"") && json.contains("\"status\":\"SUCCESS\"")) {
                loggedEvents.increment();
            }
        });

        ExecutorService executor = Executors.newFixedThreadPool(loggerThreads);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(loggerThreads);

        for (int t = 0; t < loggerThreads; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int i = 0; i < eventsPerThread; i++) {
                        auditLogger.logEvent("CONCURRENT_TEST", "jdbc/ClusterDB_" + threadId, "password", "KeyProvider", "SUCCESS", 2L);
                    }
                } catch (Exception e) {
                    fail(e);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = endGate.await(10, TimeUnit.SECONDS);
        executor.shutdown();
        auditLogger.setEventConsumer(null);

        assertTrue(completed);
        assertEquals(totalExpectedEvents, loggedEvents.sum(), "All audit events must be captured accurately under high concurrency");
    }

    @Test
    @DisplayName("Realtime Scenario 7: Tomcat JDBC Pool (VaultDataSourceFactory) high concurrency checkout & execution under 50-worker distributed load")
    void testTomcatJdbcPoolConcurrentLoadAndCheckout() throws Exception {
        int concurrency = 50;
        int queriesPerWorker = 30;
        int totalQueries = concurrency * queriesPerWorker;

        VaultCrypto crypto = new VaultCrypto("TomcatJdbcPoolKey2026!Distributed#");
        String encUser = crypto.encrypt("sa");
        String encPass = crypto.encrypt("concurrent_secret_123");

        Reference ref = new Reference("javax.sql.DataSource");
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("url", "jdbc:h2:mem:tomcat_jdbc_concurrent;DB_CLOSE_DELAY=-1"));
        ref.add(new StringRefAddr("username", encUser));
        ref.add(new StringRefAddr("password", encPass));
        ref.add(new StringRefAddr("maxActive", "50"));
        ref.add(new StringRefAddr("maxIdle", "10"));
        ref.add(new StringRefAddr("maxWait", "5000"));
        ref.add(new StringRefAddr("initialSize", "5"));

        VaultDataSourceFactory factory = new VaultDataSourceFactory(new ReferencePropertyDecryptor(crypto));
        Object obj = factory.getObjectInstance(ref, null, null, new Hashtable<>());
        assertNotNull(obj);
        assertInstanceOf(DataSource.class, obj);

        DataSource ds = (DataSource) obj;

        try (Connection initConn = ds.getConnection();
             Statement stmt = initConn.createStatement()) {
            stmt.execute("CREATE TABLE orders (id INT PRIMARY KEY, customer VARCHAR(50), amount DECIMAL(10,2))");
        }

        ExecutorService executor = Executors.newFixedThreadPool(concurrency);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(concurrency);

        LongAdder successQueries = new LongAdder();
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
        long startTime = System.nanoTime();

        for (int t = 0; t < concurrency; t++) {
            final int workerId = t;
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int i = 0; i < queriesPerWorker; i++) {
                        int orderId = workerId * 1000 + i;
                        try (Connection conn = ds.getConnection();
                             Statement stmt = conn.createStatement()) {
                            stmt.execute("INSERT INTO orders VALUES (" + orderId + ", 'Cust_" + workerId + "', " + (i * 10.5) + ")");
                            try (ResultSet rs = stmt.executeQuery("SELECT count(*) FROM orders WHERE id = " + orderId)) {
                                if (rs.next() && rs.getInt(1) == 1) {
                                    successQueries.increment();
                                }
                            }
                        }
                    }
                } catch (Throwable e) {
                    errors.add(e);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = endGate.await(20, TimeUnit.SECONDS);
        long elapsedMs = (System.nanoTime() - startTime) / 1_000_000;
        executor.shutdown();

        if (obj instanceof AutoCloseable) {
            ((AutoCloseable) obj).close();
        }

        assertTrue(completed, "Tomcat JDBC concurrent checkout timed out");
        assertTrue(errors.isEmpty(), "Errors during Tomcat JDBC checkout: " + errors);
        assertEquals(totalQueries, successQueries.sum(), "All queries should succeed across all 50 concurrent workers");

        double opsPerSec = (totalQueries * 1000.0) / Math.max(1, elapsedMs);
        System.out.printf("[Realtime Tomcat JDBC Concurrency] Queries: %d | Workers: %d | Time: %d ms | Throughput: %.0f queries/sec%n",
                totalQueries, concurrency, elapsedMs, opsPerSec);
    }

    @Test
    @DisplayName("Realtime Scenario 8: Distributed multi-process cluster simulation (independent JVM processes)")
    void testDistributedMultiProcessClusterSimulation() throws Exception {
        int clusterNodes = 4;
        String jarPath = "build/libs/tomcat-vault-2.0.0.jar";
        File jarFile = new File(jarPath);
        if (!jarFile.exists()) {
            return;
        }

        VaultCrypto crypto = new VaultCrypto("DistributedClusterMasterKey2026!");
        String testSecret = "ClusterNodeSecret_987654";
        String ciphertext = crypto.encrypt(testSecret);

        Path clusterContext = tempDir.resolve("cluster-context.xml");
        String xmlContent = "<Context>\n" +
                "  <Resource name=\"jdbc/NodeDB\" auth=\"Container\" type=\"javax.sql.DataSource\"\n" +
                "    driverClassName=\"org.h2.Driver\" url=\"jdbc:h2:mem:clusternode;DB_CLOSE_DELAY=-1\"\n" +
                "    factory=\"umrao.tomcat.vault.VaultDataSourceFactory\"\n" +
                "    username=\"" + crypto.encrypt("sa") + "\"\n" +
                "    password=\"" + crypto.encrypt("cluster_pass") + "\"\n" +
                "    maxActive=\"50\" maxIdle=\"10\" />\n" +
                "</Context>";
        Files.writeString(clusterContext, xmlContent);

        ExecutorService clusterExecutor = Executors.newFixedThreadPool(clusterNodes);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch endGate = new CountDownLatch(clusterNodes);

        List<String> outputs = Collections.synchronizedList(new ArrayList<>());
        List<Integer> exitCodes = Collections.synchronizedList(new ArrayList<>());

        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";

        for (int n = 0; n < clusterNodes; n++) {
            final int nodeId = n;
            clusterExecutor.submit(() -> {
                try {
                    startGate.await();
                    ProcessBuilder pb = new ProcessBuilder(
                            javaBin, "-jar", jarFile.getAbsolutePath(),
                            "-d", ciphertext,
                            "-k", "DistributedClusterMasterKey2026!"
                    );
                    pb.redirectErrorStream(true);
                    Process process = pb.start();
                    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    int code = process.waitFor();
                    exitCodes.add(code);
                    outputs.add("Node-" + nodeId + ": " + output.trim());
                } catch (Exception e) {
                    outputs.add("Node-" + nodeId + " error: " + e.getMessage());
                    exitCodes.add(1);
                } finally {
                    endGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean finished = endGate.await(15, TimeUnit.SECONDS);
        clusterExecutor.shutdown();

        assertTrue(finished, "Cluster simulation timed out");
        assertEquals(clusterNodes, exitCodes.size());
        for (int code : exitCodes) {
            assertEquals(0, code, "All cluster node processes should exit with code 0");
        }
        for (String output : outputs) {
            assertTrue(output.contains(testSecret), "Node output should contain decrypted secret: " + output);
        }
    }
}
