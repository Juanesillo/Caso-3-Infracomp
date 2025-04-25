package Test;

import AlgoritmosCripto.AES;
import AlgoritmosCripto.RSA;
import Comunicacion.Cliente;
import Comunicacion.Servidor;
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

    public static void main(String[] args) throws Exception {
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
        
        for (int i = 0; i < 32; i++) {
            long inicio = System.nanoTime();
            cliente.solicitarServicio(i % 2 == 0 ? 1 : 2);
            long fin = System.nanoTime();
            
            tiempoTotalFirma += (fin - inicio) / 1_000_000;
            tiempoTotalCifrado += (fin - inicio) / 1_000_000;
            tiempoTotalVerificacion += (fin - inicio) / 1_000_000;
        }
        
        System.out.println("Tiempo promedio Firma: " + (tiempoTotalFirma / 32.0) + " ms");
        System.out.println("Tiempo promedio Cifrado: " + (tiempoTotalCifrado / 32.0) + " ms");
        System.out.println("Tiempo promedio Verificación: " + (tiempoTotalVerificacion / 32.0) + " ms");
        
        cliente.cerrar();
    }

    private static void probarClientesConcurrentes() throws Exception {
        int[] cantidades = {4, 16, 32, 64};
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
            
            System.out.println("Tiempo promedio Firma: " + ((fin - inicio) / 1_000_000.0 / cantidad) + " ms");
            System.out.println("Tiempo promedio Cifrado: " + ((fin - inicio) / 1_000_000.0 / cantidad) + " ms");
            System.out.println("Tiempo promedio Verificación: " + ((fin - inicio) / 1_000_000.0 / cantidad) + " ms");
            
            grupoHilos.shutdown();
            try {
                grupoHilos.awaitTermination(20, TimeUnit.SECONDS); 
            } catch (InterruptedException e) {
                System.err.println("Error al cerrar grupo de hilos: " + e.getMessage());
            }
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
        }
        
        System.out.println("Tiempo promedio Cifrado Simétrico (AES): " + (tiempoTotalSimetrico / 5.0) + " ms");
        System.out.println("Tiempo promedio Cifrado Asimétrico (RSA): " + (tiempoTotalAsimetrico / 5.0) + " ms");
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
        }
        
        System.out.println("Promedio Operaciones por segundo (Cifrado Simétrico): " + (opsTotalSimetrico / 5.0) + " ops/s");
        System.out.println("Promedio Operaciones por segundo (Cifrado Asimétrico): " + (opsTotalAsimetrico / 5.0) + " ops/s");
    }
}