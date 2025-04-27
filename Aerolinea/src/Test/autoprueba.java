package Test;

import AlgoritmosCripto.AES;
import AlgoritmosCripto.RSA;
import Comunicacion.Cliente;
import Comunicacion.Servidor;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;

public class autoprueba {
    private static final int PUERTO = 5000;
    private static final BigInteger PRIMO = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
    private static final BigInteger GENERADOR = new BigInteger("2");
    private static final String RESULTS_DIR = "results/";

    public static void main(String[] args) throws Exception {
        // Configurar los valores de clientes concurrentes desde los argumentos
        int[] cantidades;
        if (args.length > 0) {
            cantidades = new int[args.length];
            for (int i = 0; i < args.length; i++) {
                try {
                    cantidades[i] = Integer.parseInt(args[i]);
                    if (cantidades[i] <= 0) {
                        System.err.println("Los valores deben ser mayores que 0. Usando valores por defecto.");
                        cantidades = new int[]{4, 16, 32, 64};
                        break;
                    }
                } catch (NumberFormatException e) {
                    System.err.println("Argumento inválido: " + args[i] + ". Usando valores por defecto.");
                    cantidades = new int[]{4, 16, 32, 64};
                    break;
                }
            }
        } else {
            cantidades = new int[]{4, 16, 32, 64}; // Valores por defecto
        }

        new File(RESULTS_DIR).mkdirs();

        Servidor servidor = new Servidor(PUERTO, PRIMO, GENERADOR);
        Thread hiloServidor = new Thread(() -> {
            try {
                servidor.iniciar();
            } catch (Exception e) {
                System.err.println("Error en el servidor: " + e.getMessage());
            }
        });
        hiloServidor.start();
        Thread.sleep(1000);

        probarConsultasIterativas();
        probarClientesConcurrentes(cantidades);
        compararCifrado();
        estimarVelocidadProcesador();

        servidor.detener();
        hiloServidor.join();
    }

    private static void probarConsultasIterativas() throws Exception {
        System.out.println("=== Pruebas Iterativas ===");
        Cliente cliente = new Cliente("localhost", PUERTO, PRIMO, GENERADOR);

        // Limpiar archivos previos
        new File(RESULTS_DIR + "firma_times.csv").delete();
        new File(RESULTS_DIR + "cifrado_times.csv").delete();
        new File(RESULTS_DIR + "verificacion_times.csv").delete();

        for (int i = 0; i < 32; i++) {
            cliente.solicitarServicio(i % 2 == 0 ? 1 : 2);
        }
        cliente.cerrar();

        // Calcular promedios desde los archivos generados por el servidor
        double avgFirma = calcularPromedio(RESULTS_DIR + "firma_times.csv");
        double avgCifrado = calcularPromedio(RESULTS_DIR + "cifrado_times.csv");
        double avgVerificacion = calcularPromedio(RESULTS_DIR + "verificacion_times.csv");

        System.out.println("Tiempo promedio Firma: " + avgFirma + " ms");
        System.out.println("Tiempo promedio Cifrado: " + avgCifrado + " ms");
        System.out.println("Tiempo promedio Verificación: " + avgVerificacion + " ms");

        // Guardar resultados en CSV
        try (FileWriter writer = new FileWriter(RESULTS_DIR + "iterative_tests.csv")) {
            writer.write("Prueba,Firma_ms,Cifrado_ms,Verificacion_ms\n");
            writer.write(String.format("Iterativa,%f,%f,%f\n", avgFirma, avgCifrado, avgVerificacion));
        } catch (IOException e) {
            System.err.println("Error al escribir CSV para pruebas iterativas: " + e.getMessage());
        }
    }

    private static void probarClientesConcurrentes(int[] cantidades) throws Exception {
        try (FileWriter writer = new FileWriter(RESULTS_DIR + "concurrent_tests.csv")) {
            writer.write("Delegados,Firma_ms,Cifrado_ms,Verificacion_ms\n");

            for (int cantidad : cantidades) {
                System.out.println("=== Pruebas Concurrentes: " + cantidad + " delegados ===");

                // Limpiar archivos previos
                new File(RESULTS_DIR + "firma_times.csv").delete();
                new File(RESULTS_DIR + "cifrado_times.csv").delete();
                new File(RESULTS_DIR + "verificacion_times.csv").delete();

                ExecutorService grupoHilos = Executors.newFixedThreadPool(cantidad);
                List<Future<?>> tareas = new ArrayList<>();

                for (int i = 0; i < cantidad; i++) {
                    final int id = i % 2 == 0 ? 1 : 2;
                    tareas.add(grupoHilos.submit(() -> {
                        try {
                            Cliente cliente = new Cliente("localhost", PUERTO, PRIMO, GENERADOR);
                            cliente.solicitarServicio(id);
                            cliente.cerrar();
                        } catch (Exception e) {
                            System.err.println("Error en cliente concurrente: " + e.getMessage());
                        }
                    }));
                    Thread.sleep(50);
                }

                for (Future<?> tarea : tareas) {
                    try {
                        tarea.get(20, TimeUnit.SECONDS);
                    } catch (Exception e) {
                        System.err.println("Error esperando tarea: " + e.getMessage());
                    }
                }

                grupoHilos.shutdown();
                grupoHilos.awaitTermination(20, TimeUnit.SECONDS);

                // Calcular promedios desde los archivos generados por el servidor
                double avgFirma = calcularPromedio(RESULTS_DIR + "firma_times.csv");
                double avgCifrado = calcularPromedio(RESULTS_DIR + "cifrado_times.csv");
                double avgVerificacion = calcularPromedio(RESULTS_DIR + "verificacion_times.csv");

                System.out.println("Tiempo promedio Firma: " + avgFirma + " ms");
                System.out.println("Tiempo promedio Cifrado: " + avgCifrado + " ms");
                System.out.println("Tiempo promedio Verificación: " + avgVerificacion + " ms");

                writer.write(String.format("%d,%f,%f,%f\n", cantidad, avgFirma, avgCifrado, avgVerificacion));
            }
        } catch (IOException e) {
            System.err.println("Error al escribir CSV para pruebas concurrentes: " + e.getMessage());
        }
    }

    private static double calcularPromedio(String archivo) {
        try (BufferedReader reader = new BufferedReader(new FileReader(archivo))) {
            double suma = 0;
            int count = 0;
            String linea;
            while ((linea = reader.readLine()) != null) {
                suma += Double.parseDouble(linea);
                count++;
            }
            return count > 0 ? suma / count : 0;
        } catch (IOException e) {
            System.err.println("Error al leer " + archivo + ": " + e.getMessage());
            return 0;
        }
    }

    private static void compararCifrado() throws Exception {
        System.out.println("=== Comparación Cifrado Simétrico vs Asimétrico ===");
        byte[] datos = "Mensaje de prueba".getBytes();
        byte[] claveAES = new byte[32];
        byte[] vectorInicial = AES.generarIV();

        PublicKey llavePublica = RSA.cargarLlavePublica("Llaves/LlavePublica.txt");
        PrivateKey llavePrivada = RSA.cargarLlavePrivada("Llaves/LlavePrivada.secret");

        double tiempoTotalSimetrico = 0;
        double tiempoTotalAsimetrico = 0;

        try (FileWriter writer = new FileWriter(RESULTS_DIR + "encryption_comparison.csv")) {
            writer.write("Repeticion,Simetrico_ms,Asimetrico_ms\n");

            for (int i = 1; i <= 5; i++) {
                System.out.println("Repetición " + i + ":");

                long inicioSimetrico = System.nanoTime();
                AES.encriptar(datos, claveAES, vectorInicial);
                long finSimetrico = System.nanoTime();
                double tiempoSimetrico = (finSimetrico - inicioSimetrico) / 1_000_000.0;
                tiempoTotalSimetrico += tiempoSimetrico;
                System.out.println("Tiempo Cifrado Simétrico (AES): " + tiempoSimetrico + " ms");

                long inicioAsimetrico = System.nanoTime();
                Cipher cifradorRSA = Cipher.getInstance("RSA");
                cifradorRSA.init(Cipher.ENCRYPT_MODE, llavePublica);
                cifradorRSA.doFinal(datos);
                long finAsimetrico = System.nanoTime();
                double tiempoAsimetrico = (finAsimetrico - inicioAsimetrico) / 1_000_000.0;
                tiempoTotalAsimetrico += tiempoAsimetrico;
                System.out.println("Tiempo Cifrado Asimétrico (RSA): " + tiempoAsimetrico + " ms");

                writer.write(String.format("%d,%f,%f\n", i, tiempoSimetrico, tiempoAsimetrico));
            }

            double avgSimetrico = tiempoTotalSimetrico / 5.0;
            double avgAsimetrico = tiempoTotalAsimetrico / 5.0;

            System.out.println("Tiempo promedio Cifrado Simétrico (AES): " + avgSimetrico + " ms");
            System.out.println("Tiempo promedio Cifrado Asimétrico (RSA): " + avgAsimetrico + " ms");

            writer.write(String.format("Average,%f,%f\n", avgSimetrico, avgAsimetrico));
        } catch (IOException e) {
            System.err.println("Error al escribir CSV para comparación de cifrado: " + e.getMessage());
        }
    }

    private static void estimarVelocidadProcesador() throws Exception {
        System.out.println("=== Estimación de Velocidad del Procesador ===");
        byte[] datos = "Mensaje de prueba".getBytes();
        byte[] claveAES = new byte[32];
        byte[] vectorInicial = AES.generarIV();

        PublicKey llavePublica = RSA.cargarLlavePublica("Llaves/LlavePublica.txt");
        PrivateKey llavePrivada = RSA.cargarLlavePrivada("Llaves/LlavePrivada.secret");

        double opsTotalSimetrico = 0;
        double opsTotalAsimetrico = 0;

        try (FileWriter writer = new FileWriter(RESULTS_DIR + "processor_speed.csv")) {
            writer.write("Repeticion,Simetrico_ops_s,Asimetrico_ops_s\n");

            for (int i = 1; i <= 5; i++) {
                System.out.println("Repetición " + i + ":");

                long inicioSimetrico = System.nanoTime();
                for (int j = 0; j < 1000; j++) {
                    AES.encriptar(datos, claveAES, vectorInicial);
                }
                long finSimetrico = System.nanoTime();
                double tiempoSimetrico = (finSimetrico - inicioSimetrico) / 1_000_000_000.0;
                double opsSimetrico = 1000 / tiempoSimetrico;
                opsTotalSimetrico += opsSimetrico;
                System.out.println("Operaciones por segundo (Cifrado Simétrico): " + opsSimetrico + " ops/s");

                long inicioAsimetrico = System.nanoTime();
                Cipher cifradorRSA = Cipher.getInstance("RSA");
                cifradorRSA.init(Cipher.ENCRYPT_MODE, llavePublica);
                for (int j = 0; j < 1000; j++) {
                    cifradorRSA.doFinal(datos);
                }
                long finAsimetrico = System.nanoTime();
                double tiempoAsimetrico = (finAsimetrico - inicioAsimetrico) / 1_000_000_000.0;
                double opsAsimetrico = 1000 / tiempoAsimetrico;
                opsTotalAsimetrico += opsAsimetrico;
                System.out.println("Operaciones por segundo (Cifrado Asimétrico): " + opsAsimetrico + " ops/s");

                writer.write(String.format("%d,%f,%f\n", i, opsSimetrico, opsAsimetrico));
            }

            double avgOpsSimetrico = opsTotalSimetrico / 5.0;
            double avgOpsAsimetrico = opsTotalAsimetrico / 5.0;

            System.out.println("Promedio Operaciones por segundo (Cifrado Simétrico): " + avgOpsSimetrico + " ops/s");
            System.out.println("Promedio Operaciones por segundo (Cifrado Asimétrico): " + avgOpsAsimetrico + " ops/s");

            writer.write(String.format("Average,%f,%f\n", avgOpsSimetrico, avgOpsAsimetrico));
        } catch (IOException e) {
            System.err.println("Error al escribir CSV para estimación de velocidad: " + e.getMessage());
        }
    }
}