package Comunicacion;

import AlgoritmosCripto.AES;
import AlgoritmosCripto.DH;
import AlgoritmosCripto.HMAC;
import AlgoritmosCripto.RSA;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
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
    private Map<Integer, String> servicios;
    private PublicKey publicKey; // Llave pública del servidor

    public Cliente(String direccion, int puerto, BigInteger primo, BigInteger generador) throws Exception {
        socketCliente = new Socket(direccion, puerto);
        salida = new DataOutputStream(socketCliente.getOutputStream());
        entrada = new DataInputStream(socketCliente.getInputStream());
        
        // Cargar la llave pública
        publicKey = RSA.cargarLlavePublica("Llaves/LlavePublica.txt");
        
        intercambioDH = new DH(primo, generador);
        realizarIntercambioClaves();
        this.servicios = recibirTablaServicios();
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

    private Map<Integer, String> recibirTablaServicios() throws Exception {
        // Recibir IV
        byte[] iv = new byte[entrada.readInt()];
        entrada.readFully(iv);
        
        // Recibir mensaje cifrado
        byte[] mensajeCifrado = new byte[entrada.readInt()];
        entrada.readFully(mensajeCifrado);
        
        // Recibir HMAC
        byte[] hmacRecibido = new byte[entrada.readInt()];
        entrada.readFully(hmacRecibido);
        
        // Verificar HMAC
        boolean hmacValido = HMAC.verificarHMAC(mensajeCifrado, hmacRecibido, claveHMAC);
        if (!hmacValido) {
            throw new Exception("Error en la consulta: HMAC inválido en la tabla de servicios");
        }
        
        // Desencriptar el mensaje
        byte[] mensaje = AES.desencriptar(mensajeCifrado, claveAES, iv);
        
        // Leer el mensaje: longitud de serviciosBytes + serviciosBytes + longitud de firma + firma
        ByteArrayInputStream bais = new ByteArrayInputStream(mensaje);
        DataInputStream dis = new DataInputStream(bais);
        int lenServicios = dis.readInt();
        byte[] serviciosBytes = new byte[lenServicios];
        dis.readFully(serviciosBytes);
        int lenFirma = dis.readInt();
        byte[] firma = new byte[lenFirma];
        dis.readFully(firma);
        
        // Verificar la firma
        boolean firmaValida = RSA.verificar(serviciosBytes, firma, publicKey);
        if (!firmaValida) {
            throw new Exception("Error en la consulta: Firma inválida en la tabla de servicios");
        }
        
        // Deserializar la tabla de servicios
        bais = new ByteArrayInputStream(serviciosBytes);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Map<Integer, String> servicios = (Map<Integer, String>) ois.readObject();
        
        // Mostrar los servicios al usuario
        System.out.println("Servicios disponibles:");
        for (Map.Entry<Integer, String> entry : servicios.entrySet()) {
            System.out.println("ID: " + entry.getKey() + " -> " + entry.getValue());
        }
        
        return servicios;
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
            throw new Exception("Error en la consulta: HMAC inválido en la respuesta del servidor");
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
        System.out.print("¿Cuántos clientes concurrentes desea ejecutar? (0 para modo interactivo): ");
        int numeroClientes = scanner.nextInt();

        if (numeroClientes < 0) {
            System.out.println("Por favor, ingrese un número mayor o igual a 0.");
            scanner.close();
            return;
        }

        if (numeroClientes == 0) {
            // Modo interactivo: un cliente permite al usuario seleccionar un servicio
            Cliente cliente = new Cliente("localhost", puerto, primo, generador);
            System.out.print("Ingrese el ID del servicio: ");
            int idServicio = scanner.nextInt();
            try {
                String respuesta = cliente.solicitarServicio(idServicio);
                System.out.println("Respuesta para servicio " + idServicio + ": " + respuesta);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            } finally {
                cliente.cerrar();
            }
        } else {
            // Modo concurrente: múltiples clientes, cada uno selecciona un servicio aleatoriamente
            ExecutorService grupoHilos = Executors.newFixedThreadPool(numeroClientes);
            List<Future<?>> tareas = new ArrayList<>();

            System.out.println("Iniciando " + numeroClientes + " clientes concurrentes...");
            for (int i = 0; i < numeroClientes; i++) {
                tareas.add(grupoHilos.submit(() -> {
                    try {
                        Cliente cliente = new Cliente("localhost", puerto, primo, generador);
                        Random random = new Random();
                        List<Integer> ids = new ArrayList<>(cliente.servicios.keySet());
                        int idServicio = ids.get(random.nextInt(ids.size()));
                        String respuesta = cliente.solicitarServicio(idServicio);
                        System.out.println("Cliente " + Thread.currentThread().getName() + " recibió respuesta para servicio " + idServicio + ": " + respuesta);
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
        }

        scanner.close();
        System.out.println("Todos los clientes han terminado.");
    }
}