package Test;

import AlgoritmosCripto.AES;
import AlgoritmosCripto.RSA;
import Comunicacion.Cliente;
import Comunicacion.Servidor;
import java.io.File;
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
        probarClientesConcurrentes();
        compararCifrado();
        estimarVelocidadProcesador();

        servidor.detener();
        hiloServidor.join(); 
    }

    private static void probarConsultasIterativas() throws Exception {
        System.out.println("=== Pruebas Iterativas ===");
        Cliente cliente = new Cliente("localhost", PUERTO, PRIMO, GENERADOR);
        
        long tiempoTotalFirma = 0;
        long tiempoTotalCifrado = 0;
        long tiempoTotalVerificacion = 0;
        
        String csvFile = RESULTS_DIR + "iterative_tests.csv";
        try (FileWriter writer = new FileWriter(csvFile)) {
            writer.write("Iteration,Firma_ms,Cifrado_ms,Verificacion_ms\n");
            
            for (int i = 0; i < 32; i++) {
                long inicio = System.nanoTime();
                cliente.solicitarServicio(i % 2 == 0 ? 1 : 2);
                long fin = System.nanoTime();
                
                long tiempoFirma = (fin - inicio) / 1_000_000;
                long tiempoCifrado = (fin - inicio) / 1_000_000;
                long tiempoVerificacion = (fin - inicio) / 1_000_000;
                
                tiempoTotalFirma += tiempoFirma;
                tiempoTotalCifrado += tiempoCifrado;
                tiempoTotalVerificacion += tiempoVerificacion;
                
                writer.write(String.format("%d,%d,%d,%d\n", (i + 1), tiempoFirma, tiempoCifrado, tiempoVerificacion));
            }
            
            double avgFirma = tiempoTotalFirma / 32.0;
            double avgCifrado = tiempoTotalCifrado / 32.0;
            double avgVerificacion = tiempoTotalVerificacion / 32.0;
            
            System.out.println("Tiempo promedio Firma: " + avgFirma + " ms");
            System.out.println("Tiempo promedio Cifrado: " + avgCifrado + " ms");
            System.out.println("Tiempo promedio Verificación: " + avgVerificacion + " ms");

            writer.write(String.format("Average,%f,%f,%f\n", avgFirma, avgCifrado, avgVerificacion));
        } catch (IOException e) {
            System.err.println("Error al escribir CSV para pruebas iterativas: " + e.getMessage());
        }
        
        cliente.cerrar();
    }

    private static void probarClientesConcurrentes() throws Exception {
        int[] cantidades = {4, 16, 32, 64};
        
        String csvFile = RESULTS_DIR + "concurrent_tests.csv";
        try (FileWriter writer = new FileWriter(csvFile)) {
            writer.write("Delegados,Firma_ms,Cifrado_ms,Verificacion_ms\n");
            
            for (int cantidad : cantidades) {
                System.out.println("=== Pruebas Concurrentes: " + cantidad + " delegados ===");
                
                ExecutorService grupoHilos = Executors.newFixedThreadPool(cantidad);
                List<Future<?>> tareas = new ArrayList<>();
                
                long inicio = System.nanoTime();
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
                long fin = System.nanoTime();
                
                double avgFirma = (fin - inicio) / 1_000_000.0 / cantidad;
                double avgCifrado = (fin - inicio) / 1_000_000.0 / cantidad;
                double avgVerificacion = (fin - inicio) / 1_000_000.0 / cantidad;
                
                System.out.println("Tiempo promedio Firma: " + avgFirma + " ms");
                System.out.println("Tiempo promedio Cifrado: " + avgCifrado + " ms");
                System.out.println("Tiempo promedio Verificación: " + avgVerificacion + " ms");
           
                writer.write(String.format("%d,%f,%f,%f\n", cantidad, avgFirma, avgCifrado, avgVerificacion));
                
                grupoHilos.shutdown();
                try {
                    grupoHilos.awaitTermination(20, TimeUnit.SECONDS); 
                } catch (InterruptedException e) {
                    System.err.println("Error al cerrar grupo de hilos: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error al escribir CSV para pruebas concurrentes: " + e.getMessage());
        }
    }

    private static void compararCifrado() throws Exception {
        System.out.println("=== Comparación Cifrado Simétrico vs Asimétrico ===");
        byte[] datos = "Mensaje de prueba".getBytes();
        byte[] claveAES = new byte[32];
        byte[] vectorInicial = AES.generarIV();
        
        PublicKey llavePublica = RSA.cargarLlavePublica("Keys/PublicKey.txt");
        PrivateKey llavePrivada = RSA.cargarLlavePrivada("Keys/PrivateKey.secret");
        
        double tiempoTotalSimetrico = 0;
        double tiempoTotalAsimetrico = 0;
      
        String csvFile = RESULTS_DIR + "encryption_comparison.csv";
        try (FileWriter writer = new FileWriter(csvFile)) {
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
                byte[] datosCifradosRSA = cifradorRSA.doFinal(datos);
                long finAsimetrico = System.nanoTime();
                double tiempoAsimetrico = (finAsimetrico - inicioAsimetrico) / 1_000_000.0;
                tiempoTotalAsimetrico += tiempoAsimetrico;
                System.out.println("Tiempo Cifrado Asimétrico (RSA): " + tiempoAsimetrico + " ms");
                
                // Write to CSV
                writer.write(String.format("%d,%f,%f\n", i, tiempoSimetrico, tiempoAsimetrico));
            }
            
            double avgSimetrico = tiempoTotalSimetrico / 5.0;
            double avgAsimetrico = tiempoTotalAsimetrico / 5.0;
            
            System.out.println("Tiempo promedio Cifrado Simétrico (AES): " + avgSimetrico + " ms");
            System.out.println("Tiempo promedio Cifrado Asimétrico (RSA): " + avgAsimetrico + " ms");
            
            // Write averages to CSV
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
        
        PublicKey llavePublica = RSA.cargarLlavePublica("Keys/PublicKey.txt");
        PrivateKey llavePrivada = RSA.cargarLlavePrivada("Keys/PrivateKey.secret");
        
        double opsTotalSimetrico = 0;
        double opsTotalAsimetrico = 0;
        
        String csvFile = RESULTS_DIR + "processor_speed.csv";
        try (FileWriter writer = new FileWriter(csvFile)) {
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