package Comunicacion;

import AlgoritmosCripto.RSA;
import java.math.BigInteger;
import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Servidor {
    private int puerto;
    private ServerSocket socketServidor;
    private Map<Integer, String> servicios;
    private BigInteger primo;
    private BigInteger generador;
    private ExecutorService grupoHilos;
    private volatile boolean corriendo;
    private PrivateKey privateKey; // Llave privada del servidor
    private PublicKey publicKey;   // Llave pública del servidor

    public Servidor(int puerto, BigInteger primo, BigInteger generador) throws Exception {
        this.puerto = puerto;
        this.primo = primo;
        this.generador = generador;
        servicios = new HashMap<>();
        servicios.put(1, "192.168.1.1:9001");
        servicios.put(2, "192.168.1.2:9002");
        System.out.println("Servicios disponibles:");
        servicios.forEach((id, direccion) -> System.out.println("ID: " + id + " -> " + direccion));
        grupoHilos = Executors.newFixedThreadPool(100);
        corriendo = true;

        // Cargar las llaves RSA
        privateKey = RSA.cargarLlavePrivada("Llaves/LlavePrivada.secret");
        publicKey = RSA.cargarLlavePublica("Llaves/LlavePublica.txt");
        System.out.println("Llaves RSA cargadas exitosamente.");
    }

    public void iniciar() throws Exception {
        socketServidor = new ServerSocket(puerto, 100);
        try {
            while (corriendo) {
                Socket socketCliente = socketServidor.accept();
                System.out.println("Cliente conectado: " + socketCliente.getInetAddress());
                // Pasar las llaves al ServidorDelegado
                grupoHilos.submit(new ServidorDelegado(socketCliente, servicios, primo, generador, privateKey, publicKey));
            }
        } catch (SocketException e) {
            if (!corriendo) {
                System.out.println("Servidor detenido.");
            } else {
                throw e;
            }
        } finally {
            socketServidor.close();
        }
    }

    public void detener() throws Exception {
        corriendo = false;
        if (socketServidor != null && !socketServidor.isClosed()) {
            socketServidor.close();
        }
        grupoHilos.shutdown();
        try {
            grupoHilos.awaitTermination(20, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            System.err.println("Error al cerrar grupo de hilos: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws Exception {
        int puerto = 5000;
        BigInteger primo = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
        BigInteger generador = new BigInteger("2");

        Servidor servidor = new Servidor(puerto, primo, generador);
        System.out.println("Servidor iniciado en el puerto " + puerto + "...");
        servidor.iniciar();
    }
}