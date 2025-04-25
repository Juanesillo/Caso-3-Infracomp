package Test;

import AlgoritmosCripto.*;
import Comunicacion.Cliente;
import Comunicacion.Servidor;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

public class Lab {
    public static void main(String[] args) throws Exception {
        // Iniciar el servidor en un hilo separado
        Thread serverThread = new Thread(() -> {
            try {
                Servidor.main(null);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.start();
        Thread.sleep(1000); // Dar tiempo al servidor para iniciarse

        // Número de repeticiones
        int repetitions = 5;

        // Escenario 1: Cliente iterativo con 32 consultas
        System.out.println("\n=== Escenario 1: Cliente Iterativo (32 consultas) ===");
        double[] avgSignTimesIterative = new double[repetitions];
        double[] avgEncryptTimesIterative = new double[repetitions];
        double[] avgVerifyTimesIterative = new double[repetitions];
        for (int r = 0; r < repetitions; r++) {
            System.out.println("\nRepetición " + (r + 1) + ":");
            runIterativeScenario();
            avgSignTimesIterative[r] = Servidor.getAverageSignTime();
            avgEncryptTimesIterative[r] = Servidor.getAverageEncryptTime();
            avgVerifyTimesIterative[r] = Servidor.getAverageVerifyTime();
        }
        System.out.println("\nResultados promedio (32 iterativas):");
        System.out.printf("Firma: %.3f ms\n", Arrays.stream(avgSignTimesIterative).average().orElse(0));
        System.out.printf("Cifrado: %.3f ms\n", Arrays.stream(avgEncryptTimesIterative).average().orElse(0));
        System.out.printf("Verificación: %.3f ms\n", Arrays.stream(avgVerifyTimesIterative).average().orElse(0));

        // Escenario 2: Clientes concurrentes (4, 16, 32, 64 delegados)
        System.out.println("\n=== Escenario 2: Clientes Concurrentes ===");
        int[] numDelegates = {4, 16, 32, 64};
        for (int delegates : numDelegates) {
            System.out.println("\n-- Probando con " + delegates + " delegados --");
            double[] avgSignTimesConcurrent = new double[repetitions];
            double[] avgEncryptTimesConcurrent = new double[repetitions];
            double[] avgVerifyTimesConcurrent = new double[repetitions];
            for (int r = 0; r < repetitions; r++) {
                System.out.println("\nRepetición " + (r + 1) + ":");
                runConcurrentScenario(delegates);
                avgSignTimesConcurrent[r] = Servidor.getAverageSignTime();
                avgEncryptTimesConcurrent[r] = Servidor.getAverageEncryptTime();
                avgVerifyTimesConcurrent[r] = Servidor.getAverageVerifyTime();
            }
            System.out.println("\nResultados promedio (" + delegates + " delegados):");
            System.out.printf("Firma: %.3f ms\n", Arrays.stream(avgSignTimesConcurrent).average().orElse(0));
            System.out.printf("Cifrado: %.3f ms\n", Arrays.stream(avgEncryptTimesConcurrent).average().orElse(0));
            System.out.printf("Verificación: %.3f ms\n", Arrays.stream(avgVerifyTimesConcurrent).average().orElse(0));
        }

        // Comparación de cifrado simétrico vs asimétrico
        System.out.println("\n=== Comparación Cifrado Simétrico vs Asimétrico ===");
        double[] symmetricTimes = new double[repetitions];
        double[] asymmetricTimes = new double[repetitions];
        for (int r = 0; r < repetitions; r++) {
            System.out.println("\nRepetición " + (r + 1) + ":");
            double[] times = compareEncryption();
            symmetricTimes[r] = times[0];
            asymmetricTimes[r] = times[1];
        }
        System.out.println("\nResultados promedio:");
        System.out.printf("Tiempo Cifrado Simétrico (AES): %.3f ms\n", Arrays.stream(symmetricTimes).average().orElse(0));
        System.out.printf("Tiempo Cifrado Asimétrico (RSA - clave AES): %.3f ms\n", Arrays.stream(asymmetricTimes).average().orElse(0));

        // Estimación de velocidad del procesador
        System.out.println("\n=== Estimación de Velocidad del Procesador ===");
        double[] symmetricOps = new double[repetitions];
        double[] asymmetricOps = new double[repetitions];
        for (int r = 0; r < repetitions; r++) {
            System.out.println("\nRepetición " + (r + 1) + ":");
            double[] ops = estimateProcessorSpeed();
            symmetricOps[r] = ops[0];
            asymmetricOps[r] = ops[1];
        }
        System.out.println("\nResultados promedio:");
        System.out.printf("Operaciones por segundo (Cifrado Simétrico): %.2f ops/s\n", Arrays.stream(symmetricOps).average().orElse(0));
        System.out.printf("Operaciones por segundo (Cifrado Asimétrico): %.2f ops/s\n", Arrays.stream(asymmetricOps).average().orElse(0));

        // Detener el servidor
        serverThread.interrupt();
    }

    private static void runIterativeScenario() throws Exception {
        Servidor.resetTimes();
        for (int i = 0; i < 32; i++) {
            int serviceId = (i % 2) + 1; // Alterna entre servicio 1 y 2
            Cliente.ejecutarCliente(serviceId);
            Thread.sleep(100);
        }

        // Imprimir tiempos promedio
        System.out.printf("Tiempo promedio Firma: %.3f ms\n", Servidor.getAverageSignTime());
        System.out.printf("Tiempo promedio Cifrado: %.3f ms\n", Servidor.getAverageEncryptTime());
        System.out.printf("Tiempo promedio Verificación: %.3f ms\n", Servidor.getAverageVerifyTime());
    }

    private static void runConcurrentScenario(int numDelegates) throws Exception {
        Servidor.resetTimes();
        ExecutorService executor = Executors.newFixedThreadPool(Math.min(numDelegates, 16));
        List<Future<Void>> futures = new ArrayList<>();

        for (int i = 0; i < numDelegates; i++) {
            final int serviceId = (i % 2) + 1; // Alterna entre servicio 1 y 2
            futures.add(executor.submit(() -> {
                Cliente.ejecutarCliente(serviceId);
                return null;
            }));
            Thread.sleep(50);
        }

        // Esperar a que todos los clientes terminen
        for (Future<Void> future : futures) {
            try {
                future.get(20, TimeUnit.SECONDS);
            } catch (Exception e) {
                System.err.println("Error en cliente concurrente: " + e.getMessage());
            }
        }

        // Imprimir tiempos promedio
        System.out.printf("Tiempo promedio Firma: %.3f ms\n", Servidor.getAverageSignTime());
        System.out.printf("Tiempo promedio Cifrado: %.3f ms\n", Servidor.getAverageEncryptTime());
        System.out.printf("Tiempo promedio Verificación: %.3f ms\n", Servidor.getAverageVerifyTime());

        executor.shutdown();
        executor.awaitTermination(60, TimeUnit.SECONDS);
    }

    private static double[] compareEncryption() throws Exception {
        // Generar claves y datos de prueba
        DHParameterSpec dhSpec = DHUtil.generateParams();
        DHUtil dhUtil = new DHUtil(dhSpec.getP(), dhSpec.getG());
        KeyPair keyPair = dhUtil.generateKeyPair();
        byte[] sharedSecret = dhUtil.computeSharedSecret(keyPair.getPrivate(), keyPair.getPublic());
        byte[][] sessionKeys = DHUtil.generateSessionKeys(sharedSecret);
        byte[] kAB1 = sessionKeys[0];

        // Datos de prueba
        byte[] datosPrueba = "Datos de prueba para cifrado".getBytes();

        // Cifrado simétrico (AES)
        byte[] ivBytes = AESUtil.generateIV();
        long startSymmetric = System.nanoTime();
        AESUtil.encrypt(datosPrueba, kAB1, ivBytes);
        long endSymmetric = System.nanoTime();
        double symmetricTime = (endSymmetric - startSymmetric) / 1_000_000.0;

        // Cifrado asimétrico (RSA) - Enfoque híbrido
        PublicKey publicKey = RSAUtil.cargarLlavePublica("Keys/PublicKey.txt");
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Generar una clave AES temporal para el enfoque híbrido
        byte[] tempAESKey = AESUtil.generateIV();
        byte[] encryptedData = AESUtil.encrypt(datosPrueba, tempAESKey, ivBytes);

        // Cifrar la clave AES con RSA
        long startAsymmetric = System.nanoTime();
        byte[] encryptedKey = rsaCipher.doFinal(tempAESKey);
        long endAsymmetric = System.nanoTime();
        double asymmetricTime = (endAsymmetric - startAsymmetric) / 1_000_000.0;

        System.out.printf("Tiempo Cifrado Simétrico (AES): %.3f ms\n", symmetricTime);
        System.out.printf("Tiempo Cifrado Asimétrico (RSA - clave AES): %.3f ms\n", asymmetricTime);

        return new double[]{symmetricTime, asymmetricTime};
    }

    private static double[] estimateProcessorSpeed() throws Exception {
        // Generar claves y datos de prueba
        DHParameterSpec dhSpec = DHUtil.generateParams();
        DHUtil dhUtil = new DHUtil(dhSpec.getP(), dhSpec.getG());
        KeyPair keyPair = dhUtil.generateKeyPair();
        byte[] sharedSecret = dhUtil.computeSharedSecret(keyPair.getPrivate(), keyPair.getPublic());
        byte[][] sessionKeys = DHUtil.generateSessionKeys(sharedSecret);
        byte[] kAB1 = sessionKeys[0];

        // Datos de prueba
        byte[] datosPrueba = "Datos de prueba para cifrado".getBytes();

        int iterations = 1000;
        byte[] ivBytes = AESUtil.generateIV();

        // Velocidad cifrado simétrico
        long startSymmetric = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            AESUtil.encrypt(datosPrueba, kAB1, ivBytes);
        }
        long endSymmetric = System.nanoTime();
        double symmetricTimeSeconds = (endSymmetric - startSymmetric) / 1_000_000_000.0;
        double symmetricOpsPerSecond = iterations / symmetricTimeSeconds;

        // Velocidad cifrado asimétrico
        PublicKey publicKey = RSAUtil.cargarLlavePublica("Keys/PublicKey.txt");
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] tempAESKey = AESUtil.generateIV();
        long startAsymmetric = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            rsaCipher.doFinal(tempAESKey);
        }
        long endAsymmetric = System.nanoTime();
        double asymmetricTimeSeconds = (endAsymmetric - startAsymmetric) / 1_000_000_000.0;
        double asymmetricOpsPerSecond = iterations / asymmetricTimeSeconds;

        System.out.printf("Operaciones por segundo (Cifrado Simétrico): %.2f ops/s\n", symmetricOpsPerSecond);
        System.out.printf("Operaciones por segundo (Cifrado Asimétrico): %.2f ops/s\n", asymmetricOpsPerSecond);

        return new double[]{symmetricOpsPerSecond, asymmetricOpsPerSecond};
    }
}