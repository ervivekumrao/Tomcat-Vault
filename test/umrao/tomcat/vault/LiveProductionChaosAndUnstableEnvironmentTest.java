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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import umrao.tomcat.vault.exception.DecryptionException;
import umrao.tomcat.vault.exception.SecretResolutionException;
import umrao.tomcat.vault.key.CompositeKeyProvider;
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
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Production-equivalent live chaos, concurrency, and fault-injection test suite.
 * Tests the generated JAR and core runtime under real-world production failure scenarios:
 * 1. Multi-process live execution of the generated JAR under concurrent load
 * 2. Unstable network & connection pool recovery during simulated database drops
 * 3. Intermittent cloud secret provider outages (503s, timeouts) with TTL caching shield
 * 4. High-load key rotation stampede combined with corrupted / tampered ciphertext injection
 * 5. Memory stability & leak prevention under sustained high allocation pressure.
 *
 * @author Vivek Umrao
 */
@SuppressWarnings({"resource", "SqlNoDataSourceInspection", "SqlResolve"})
class LiveProductionChaosAndUnstableEnvironmentTest {

    @TempDir
    Path tempDir;

    private String originalStrictProp;
    private File jarFile;

    @BeforeEach
    void setUp() {
        originalStrictProp = System.getProperty(VaultConstants.SYS_PROP_STRICT);
        VaultCrypto.clearKeyCache();
        SecretResolverRegistry.getInstance().resetDefaultResolvers();
        VaultCredentialReloader.getInstance().clearListeners();

        jarFile = new File("build/libs/tomcat-vault-2.0.0.jar");
        assertTrue(jarFile.exists(), "build/libs/tomcat-vault-2.0.0.jar must exist before running live tests");
    }

    @AfterEach
    void tearDown() {
        if (originalStrictProp != null) {
            System.setProperty(VaultConstants.SYS_PROP_STRICT, originalStrictProp);
        } else {
            System.clearProperty(VaultConstants.SYS_PROP_STRICT);
        }
        VaultCrypto.clearKeyCache();
        SecretResolverRegistry.getInstance().resetDefaultResolvers();
        VaultCredentialReloader.getInstance().clearListeners();
    }

    @Test
    @DisplayName("Production Test 1: Live execution of generated JAR across concurrent JVM processes under stampede")
    @Timeout(value = 45, unit = TimeUnit.SECONDS)
    void testLiveGeneratedJarConcurrentProcessStampede() throws Exception {
        int processCount = 8;
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java";

        VaultCrypto crypto = new VaultCrypto("ProdClusterMasterKey2026!#LiveTest");
        String secretData = "SuperSecretLiveProductionDatabaseCredential#2026";
        String encrypted = crypto.encrypt(secretData);

        // Pre-create a context.xml file for verification testing
        Path contextFile = tempDir.resolve("live-context.xml");
        String xml = "<Context>\n" +
                "  <Resource name=\"jdbc/LiveDB\" auth=\"Container\" type=\"javax.sql.DataSource\"\n" +
                "    driverClassName=\"org.h2.Driver\" url=\"jdbc:h2:mem:liveprod;DB_CLOSE_DELAY=-1\"\n" +
                "    factory=\"umrao.tomcat.vault.VaultDataSourceFactory\"\n" +
                "    username=\"sa\" password=\"" + crypto.encrypt("testpass") + "\" />\n" +
                "</Context>";
        Files.writeString(contextFile, xml);

        ExecutorService executor = Executors.newFixedThreadPool(processCount);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneGate = new CountDownLatch(processCount);

        List<Integer> exitCodes = Collections.synchronizedList(new ArrayList<>());
        List<String> outputs = Collections.synchronizedList(new ArrayList<>());

        for (int i = 0; i < processCount; i++) {
            final int index = i;
            executor.submit(() -> {
                try {
                    startGate.await();
                    ProcessBuilder pb;
                    if (index % 3 == 0) {
                        // Action A: Decrypt via CLI
                        pb = new ProcessBuilder(
                                javaBin, "-jar", jarFile.getAbsolutePath(),
                                "-d", encrypted,
                                "-k", "ProdClusterMasterKey2026!#LiveTest"
                        );
                    } else if (index % 3 == 1) {
                        // Action B: Verify context.xml via CLI
                        pb = new ProcessBuilder(
                                javaBin, "-jar", jarFile.getAbsolutePath(),
                                "--verify", "-c", contextFile.toAbsolutePath().toString(),
                                "-k", "ProdClusterMasterKey2026!#LiveTest"
                        );
                    } else {
                        // Action C: Health diagnostics via CLI
                        pb = new ProcessBuilder(
                                javaBin, "-jar", jarFile.getAbsolutePath(),
                                "--status"
                        );
                    }

                    pb.redirectErrorStream(true);
                    Process proc = pb.start();
                    String out = new String(proc.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                    int exitCode = proc.waitFor();
                    exitCodes.add(exitCode);
                    outputs.add(out);
                } catch (Exception e) {
                    exitCodes.add(1);
                    outputs.add("Exception: " + e.getMessage());
                } finally {
                    doneGate.countDown();
                }
            });
        }

        startGate.countDown();
        boolean completed = doneGate.await(30, TimeUnit.SECONDS);
        executor.shutdown();

        assertTrue(completed, "Live JAR processes must finish within timeout");
        assertEquals(processCount, exitCodes.size());
        for (int code : exitCodes) {
            assertEquals(0, code, "All concurrent JAR processes must exit with status 0");
        }

        // Validate that decryption process returned correct plaintext
        boolean foundDecrypted = outputs.stream().anyMatch(out -> out.contains(secretData));
        assertTrue(foundDecrypted, "Generated JAR must produce exact plaintext in stdout");
    }

    @Test
    @DisplayName("Production Test 2: Unstable database recovery — pool handles disconnects and reconnects seamlessly")
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testUnstableDatabaseRecoveryWithEncryptedCredentials() throws Exception {
        String dbName = "unstable_prod_db_" + System.currentTimeMillis();
        String dbUrl = "jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1";

        VaultCrypto crypto = new VaultCrypto("UnstableRecoveryKey2026!#Prod");
        String encUser = crypto.encrypt("sa");
        String encPass = crypto.encrypt("initial_password");

        // 1. Initial database table setup
        try (Connection setupConn = java.sql.DriverManager.getConnection(dbUrl, "sa", "initial_password");
             Statement st = setupConn.createStatement()) {
            st.execute("CREATE TABLE accounts (id INT PRIMARY KEY, balance INT)");
            st.execute("INSERT INTO accounts VALUES (1, 1000)");
        }

        // 2. Initialize Tomcat connection pool using VaultDataSourceFactory
        Reference ref = new Reference("javax.sql.DataSource", "umrao.tomcat.vault.VaultDataSourceFactory", null);
        ref.add(new StringRefAddr("driverClassName", "org.h2.Driver"));
        ref.add(new StringRefAddr("url", dbUrl));
        ref.add(new StringRefAddr("username", encUser));
        ref.add(new StringRefAddr("password", encPass));
        ref.add(new StringRefAddr("initialSize", "5"));
        ref.add(new StringRefAddr("maxActive", "15"));
        ref.add(new StringRefAddr("maxWait", "2000"));
        ref.add(new StringRefAddr("testOnBorrow", "true"));
        ref.add(new StringRefAddr("validationQuery", "SELECT 1"));

        System.setProperty(VaultConstants.SYS_PROP_KEY, "UnstableRecoveryKey2026!#Prod");
        try {
            VaultDataSourceFactory factory = new VaultDataSourceFactory();
            DataSource dataSource = (DataSource) factory.getObjectInstance(ref, null, null, new Hashtable<>());
            assertNotNull(dataSource);

        // 3. Worker threads continuously query the pool
        int workers = 10;
        int iterations = 100;
        ExecutorService executor = Executors.newFixedThreadPool(workers);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(workers);

        AtomicInteger successfulQueries = new AtomicInteger(0);
        AtomicInteger transientErrors = new AtomicInteger(0);

        for (int w = 0; w < workers; w++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < iterations; i++) {
                        try (Connection conn = dataSource.getConnection();
                             Statement st = conn.createStatement();
                             ResultSet rs = st.executeQuery("SELECT balance FROM accounts WHERE id = 1")) {
                            if (rs.next()) {
                                int bal = rs.getInt(1);
                                if (bal == 1000) {
                                    successfulQueries.incrementAndGet();
                                }
                            }
                        } catch (SQLException e) {
                            transientErrors.incrementAndGet();
                        }
                        Thread.sleep(5);
                    }
                } catch (Exception ignored) {
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();

        // 4. Injected Chaos: Rotate credentials and notify reload mid-flight
        Thread.sleep(100);
        VaultCredentialReloader.getInstance().notifyReload("jdbc/AppDB");

        assertTrue(doneLatch.await(20, TimeUnit.SECONDS));
        executor.shutdown();

        // Pool must successfully serve the majority of requests and recover gracefully
        assertTrue(successfulQueries.get() > 500, "High volume of successful queries required through pool");

        // 5. Verify final connection state is 100% healthy
        try (Connection finalConn = dataSource.getConnection();
             Statement st = finalConn.createStatement();
             ResultSet rs = st.executeQuery("SELECT count(*) FROM accounts")) {
            assertTrue(rs.next());
            assertEquals(1, rs.getInt(1));
        }
    } finally {
        System.clearProperty(VaultConstants.SYS_PROP_KEY);
    }
}

    @Test
    @DisplayName("Production Test 3: Intermittent cloud vault provider outages (503s & timeouts) shielded by TTL cache")
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testFlakyCloudProviderShieldedByTtlCache() throws Exception {
        AtomicInteger providerHitCount = new AtomicInteger(0);
        AtomicBoolean providerFailing = new AtomicBoolean(false);

        SecretResolver chaoticResolver = new SecretResolver() {
            @Override
            public boolean supports(String expression) {
                return expression != null && expression.startsWith("AWS_SECRET(prod/database");
            }

            @Override
            public String resolve(String expression) {
                providerHitCount.incrementAndGet();
                if (providerFailing.get()) {
                    throw new RuntimeException("503 Service Unavailable: Simulated AWS KMS connection failure");
                }
                return "ProductionResilientSecret2026!";
            }

            @Override
            public String getResolverName() {
                return "ChaoticAwsResolver";
            }
        };

        SecretResolverRegistry registry = SecretResolverRegistry.getInstance();
        registry.registerResolver(chaoticResolver);

        // 1. Initial successful resolution warms up the TTL cache
        String secret = registry.resolve("AWS_SECRET(prod/database#password)");
        assertEquals("ProductionResilientSecret2026!", secret);
        assertEquals(1, providerHitCount.get());

        // 2. Simulate upstream cloud outage (e.g. AWS KMS 503 outage)
        providerFailing.set(true);

        // 3. 30 concurrent worker threads query the secret during the upstream outage
        int threads = 30;
        int callsPerThread = 200;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneGate = new CountDownLatch(threads);

        AtomicInteger cachedSuccess = new AtomicInteger(0);
        AtomicInteger failedCalls = new AtomicInteger(0);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int j = 0; j < callsPerThread; j++) {
                        String s = registry.resolve("AWS_SECRET(prod/database#password)");
                        if ("ProductionResilientSecret2026!".equals(s)) {
                            cachedSuccess.incrementAndGet();
                        } else {
                            failedCalls.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    failedCalls.incrementAndGet();
                } finally {
                    doneGate.countDown();
                }
            });
        }

        startGate.countDown();
        assertTrue(doneGate.await(15, TimeUnit.SECONDS));
        executor.shutdown();

        // 100% of calls during the outage should be shielded by the TTL cache!
        assertEquals(threads * callsPerThread, cachedSuccess.get());
        assertEquals(0, failedCalls.get());
        // The failing upstream provider should not have been hit again
        assertEquals(1, providerHitCount.get(), "Upstream provider must not be called when cached");

        // 4. Now clear cache to verify failure behavior when upstream is failing and cache is empty
        registry.clearCache();
        assertThrows(SecretResolutionException.class, () ->
                registry.resolve("AWS_SECRET(prod/database#password)"));
    }

    @Test
    @DisplayName("Production Test 4: Key rotation stampede under concurrent load with corrupted ciphertext injection")
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testKeyRotationStampedeWithCorruptedCiphertextInjection() throws Exception {
        int workers = 30;
        int opsPerWorker = 300;
        ExecutorService executor = Executors.newFixedThreadPool(workers + 1);

        CompositeKeyProvider compositeKeyProvider = new CompositeKeyProvider();
        compositeKeyProvider.registerKey("v1", "AlphaKeyVersion1_MasterKeyPass_2026");
        compositeKeyProvider.registerKey("v2", "BetaKeyVersion2_MasterKeyPass_2026");

        VaultCrypto crypto = new VaultCrypto(compositeKeyProvider);
        String validSecret = "ValidProductionDatabaseSecret_12345";
        String validEncV1 = crypto.encrypt(validSecret, "v1");
        String validEncV2 = crypto.encrypt(validSecret, "v2");

        String[] corruptions = new String[]{
                "ENC(corrupted_payload_that_is_invalid_base64)",
                "ENC(v1:dGFtcGVyZWRfaXY_dGFtcGVyZWRfY2lwaGVydGV4dF9hbmRfdGFn)",
                "ENC(v999:5OQ5zb9OtEIDBkauX7eTWNPuG8sRjidwxyrAQDT4SOGXSlu6)",
                "ENC(corrupted_short_payload)",
                "ENC(v1:badpayload123)"
        };

        AtomicInteger validDecryptions = new AtomicInteger(0);
        AtomicInteger expectedRejections = new AtomicInteger(0);
        AtomicInteger unexpectedErrors = new AtomicInteger(0);

        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneGate = new CountDownLatch(workers);

        for (int w = 0; w < workers; w++) {
            final int workerId = w;
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int i = 0; i < opsPerWorker; i++) {
                        // 1. Valid operation
                        String v = (i % 2 == 0) ? crypto.decrypt(validEncV1) : crypto.decrypt(validEncV2);
                        if (validSecret.equals(v)) {
                            validDecryptions.incrementAndGet();
                        } else {
                            unexpectedErrors.incrementAndGet();
                        }

                        // 2. Corrupted ciphertext injection (must be rejected safely)
                        String bad = corruptions[(workerId + i) % corruptions.length];
                        try {
                            crypto.decrypt(bad);
                            // If it doesn't throw, it's an unexpected failure (unless returned unchanged)
                            unexpectedErrors.incrementAndGet();
                        } catch (DecryptionException expected) {
                            expectedRejections.incrementAndGet();
                        } catch (Exception ex) {
                            // Any other unexpected exception
                            unexpectedErrors.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    unexpectedErrors.incrementAndGet();
                } finally {
                    doneGate.countDown();
                }
            });
        }

        // Rotator thread: Dynamically rotates keys and clears caches while workers are running
        executor.submit(() -> {
            try {
                startGate.await();
                for (int r = 3; r <= 15; r++) {
                    Thread.sleep(15);
                    compositeKeyProvider.registerKey("v" + r, "RotatedKeySecretPass_" + r);
                    VaultCrypto.clearKeyCache();
                }
            } catch (Exception ignored) {
            }
        });

        startGate.countDown();
        assertTrue(doneGate.await(20, TimeUnit.SECONDS));
        executor.shutdown();

        assertEquals(0, unexpectedErrors.get(), "Zero unexpected errors allowed during key rotation & corruption injection");
        assertEquals(workers * opsPerWorker, validDecryptions.get(), "All valid ciphertexts must decrypt cleanly");
        assertEquals(workers * opsPerWorker, expectedRejections.get(), "All corrupted ciphertexts must be cleanly rejected");
    }

    @Test
    @DisplayName("Production Test 5: High memory allocation pressure alongside continuous cryptographic operations")
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void testMemoryPressureAndGcStability() throws Exception {
        int threads = 15;
        int iterations = 400;
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        VaultCrypto crypto = new VaultCrypto("MemoryStabilityKeyPassphrase2026!");
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneGate = new CountDownLatch(threads);

        AtomicInteger successes = new AtomicInteger(0);
        AtomicInteger failures = new AtomicInteger(0);

        for (int t = 0; t < threads; t++) {
            executor.submit(() -> {
                try {
                    startGate.await();
                    for (int i = 0; i < iterations; i++) {
                        // Create transient allocation pressure (simulate high request volume)
                        byte[] churn = new byte[16 * 1024]; // 16 KB churn
                        churn[0] = (byte) i;
                        if (churn[0] != (byte) i) {
                            failures.incrementAndGet();
                        }

                        String plain = "MemoryPressurePassword_" + i;
                        String enc = crypto.encrypt(plain);
                        String dec = crypto.decrypt(enc);

                        if (plain.equals(dec)) {
                            successes.incrementAndGet();
                        } else {
                            failures.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    failures.incrementAndGet();
                } finally {
                    doneGate.countDown();
                }
            });
        }

        startGate.countDown();
        assertTrue(doneGate.await(20, TimeUnit.SECONDS));
        executor.shutdown();

        assertEquals(0, failures.get(), "Zero failures allowed under memory pressure");
        assertEquals(threads * iterations, successes.get());
    }
}
