package Comunicacion;

import AlgoritmosCripto.AES;
import AlgoritmosCripto.DH;
import AlgoritmosCripto.HMAC;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Cliente {
    private Socket socketCliente;
    private DataOutputStream salida;
    private DataInputStream entrada;
    private byte[] claveAES;
    private byte[] claveHMAC;
    private DH intercambioDH;

    public Cliente(String direccion, int puerto, BigInteger primo, BigInteger generador) throws Exception {
        socketCliente = new Socket(direccion, puerto);
        salida = new DataOutputStream(socketCliente.getOutputStream());
        entrada = new DataInputStream(socketCliente.getInputStream());
        
        intercambioDH = new DH(primo, generador);
        realizarIntercambioClaves();
    }

    private void realizarIntercambioClaves() throws Exception {
        KeyPair parClaves = intercambioDH.generarParDeClaves();
        PrivateKey clavePrivada = parClaves.getPrivate();
        PublicKey clavePublica = parClaves.getPublic();
        
        intercambioDH.enviarClavePublica(salida, clavePublica);
        PublicKey clavePublicaServidor = intercambioDH.decodificarClavePublica(entrada);
        
        byte[] secretoCompartido = intercambioDH.calcularSecretoCompartido(clavePrivada, clavePublicaServidor);
        byte[][] clavesSesion = DH.generarClavesDeSesion(secretoCompartido);
        claveAES = clavesSesion[0];
        claveHMAC = clavesSesion[1];
    }

    public String solicitarServicio(int idServicio) throws Exception {
        byte[] vectorInicial = AES.generarIV();
        
        salida.writeInt(vectorInicial.length);
        salida.write(vectorInicial);
        
        String mensaje = String.valueOf(idServicio);
        byte[] datos = mensaje.getBytes();
        byte[] datosCifrados = AES.encriptar(datos, claveAES, vectorInicial);
        
        salida.writeInt(datosCifrados.length);
        salida.write(datosCifrados);
        
        byte[] hmac = HMAC.generarHMAC(datosCifrados, claveHMAC);
        salida.writeInt(hmac.length);
        salida.write(hmac);
        
        byte[] vectorInicialRespuesta = new byte[entrada.readInt()];
        entrada.readFully(vectorInicialRespuesta);
        
        byte[] datosCifradosRespuesta = new byte[entrada.readInt()];
        entrada.readFully(datosCifradosRespuesta);
        
        byte[] hmacRespuesta = new byte[entrada.readInt()];
        entrada.readFully(hmacRespuesta);
        
        boolean hmacValido = HMAC.verificarHMAC(datosCifradosRespuesta, hmacRespuesta, claveHMAC);
        if (!hmacValido) {
            throw new Exception("HMAC inválido en la respuesta del servidor");
        }
        
        byte[] datosDescifrados = AES.desencriptar(datosCifradosRespuesta, claveAES, vectorInicialRespuesta);
        return new String(datosDescifrados);
    }

    public void cerrar() throws Exception {
        salida.close();
        entrada.close();
        socketCliente.close();
    }

    public static void main(String[] args) throws Exception {
        int puerto = 5000;
        BigInteger primo = new BigInteger("179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007");
        BigInteger generador = new BigInteger("2");

        Scanner scanner = new Scanner(System.in);
        System.out.print("¿Cuántos clientes concurrentes desea ejecutar? ");
        int numeroClientes = scanner.nextInt();

        if (numeroClientes <= 0) {
            System.out.println("Por favor, ingrese un número mayor que 0.");
            scanner.close();
            return;
        }

        ExecutorService grupoHilos = Executors.newFixedThreadPool(numeroClientes);
        List<Future<?>> tareas = new ArrayList<>();

        System.out.println("Iniciando " + numeroClientes + " clientes concurrentes...");

        for (int i = 0; i < numeroClientes; i++) {
            final int idServicio = i % 2 == 0 ? 1 : 2;
            tareas.add(grupoHilos.submit(() -> {
                try {
                    Cliente cliente = new Cliente("localhost", puerto, primo, generador);
                    String respuesta = cliente.solicitarServicio(idServicio);
                    System.out.println("Cliente " + Thread.currentThread().getName() + " recibió respuesta: " + respuesta);
                    cliente.cerrar();
                } catch (Exception e) {
                    System.err.println("Error en cliente " + Thread.currentThread().getName() + ": " + e.getMessage());
                }
            }));
        }

        for (Future<?> tarea : tareas) {
            try {
                tarea.get();
            } catch (Exception e) {
                System.err.println("Error esperando tarea: " + e.getMessage());
            }
        }

        grupoHilos.shutdown();
        scanner.close();
        System.out.println("Todos los clientes han terminado.");
    }
}