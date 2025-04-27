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
import java.util.Map;

public class ServidorDelegado implements Runnable {
    private Socket socketCliente;
    private Map<Integer, String> servicios;
    private DataInputStream entrada;
    private DataOutputStream salida;
    private byte[] claveAES;
    private byte[] claveHMAC;
    private DH intercambioDH;

    public ServidorDelegado(Socket socket, Map<Integer, String> servicios, BigInteger primo, BigInteger generador) throws Exception {
        this.socketCliente = socket;
        this.servicios = servicios;
        entrada = new DataInputStream(socketCliente.getInputStream());
        salida = new DataOutputStream(socketCliente.getOutputStream());
        
        intercambioDH = new DH(primo, generador);
        realizarIntercambioClaves();
        enviarTablaServicios(); // Enviar la tabla de servicios después del intercambio de claves
    }

    private void realizarIntercambioClaves() throws Exception {
        KeyPair parClaves = intercambioDH.generarParDeClaves();
        PrivateKey clavePrivada = parClaves.getPrivate();
        PublicKey clavePublica = parClaves.getPublic();
        
        PublicKey clavePublicaCliente = intercambioDH.decodificarClavePublica(entrada);
        intercambioDH.enviarClavePublica(salida, clavePublica);
        
        byte[] secretoCompartido = intercambioDH.calcularSecretoCompartido(clavePrivada, clavePublicaCliente);
        byte[][] clavesSesion = DH.generarClavesDeSesion(secretoCompartido);
        claveAES = clavesSesion[0];
        claveHMAC = clavesSesion[1];
    }

    private void enviarTablaServicios() throws Exception {
        // Cargar la llave privada
        PrivateKey privateKey = RSA.cargarLlavePrivada("Llaves/LlavePrivada.secret");
        
        // Serializar la tabla de servicios
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(servicios);
        byte[] serviciosBytes = baos.toByteArray();
        
        // Firmar los datos
        byte[] firma = RSA.firmar(serviciosBytes, privateKey);
        
        // Crear el mensaje: longitud de serviciosBytes + serviciosBytes + longitud de firma + firma
        baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(serviciosBytes.length);
        dos.write(serviciosBytes);
        dos.writeInt(firma.length);
        dos.write(firma);
        byte[] mensaje = baos.toByteArray();
        
        // Generar IV
        byte[] iv = AES.generarIV();
        
        // Encriptar el mensaje
        byte[] mensajeCifrado = AES.encriptar(mensaje, claveAES, iv);
        
        // Generar HMAC del mensaje cifrado
        byte[] hmac = HMAC.generarHMAC(mensajeCifrado, claveHMAC);
        
        // Enviar IV, mensaje cifrado y HMAC
        salida.writeInt(iv.length);
        salida.write(iv);
        salida.writeInt(mensajeCifrado.length);
        salida.write(mensajeCifrado);
        salida.writeInt(hmac.length);
        salida.write(hmac);
    }

    @Override
    public void run() {
        try {
            // Bucle para manejar múltiples solicitudes del mismo cliente
            while (true) {
                System.out.println("IV recibido para cliente " + socketCliente.getInetAddress());
                
                byte[] vectorInicial = new byte[entrada.readInt()];
                entrada.readFully(vectorInicial);
                System.out.println("Solicitud cifrada recibida (" + vectorInicial.length + " bytes) para cliente " + socketCliente.getInetAddress());
                
                byte[] datosCifrados = new byte[entrada.readInt()];
                entrada.readFully(datosCifrados);
                System.out.println("HMAC recibido para cliente " + socketCliente.getInetAddress());
                
                byte[] hmacRecibido = new byte[entrada.readInt()];
                entrada.readFully(hmacRecibido);
                
                boolean hmacValido = HMAC.verificarHMAC(datosCifrados, hmacRecibido, claveHMAC);
                if (!hmacValido) {
                    throw new Exception("HMAC inválido");
                }
                
                byte[] datosDescifrados = AES.desencriptar(datosCifrados, claveAES, vectorInicial);
                int idServicio = Integer.parseInt(new String(datosDescifrados));
                System.out.println("Cliente " + socketCliente.getInetAddress() + " solicitó el servicio ID: " + idServicio);
                
                String direccionServicio = servicios.get(idServicio);
                if (direccionServicio == null) {
                    direccionServicio = "-1,-1";
                }
                System.out.println("Enviando respuesta al cliente " + socketCliente.getInetAddress() + ": " + direccionServicio);
                
                byte[] vectorInicialRespuesta = AES.generarIV();
                salida.writeInt(vectorInicialRespuesta.length);
                salida.write(vectorInicialRespuesta);
                
                byte[] datosRespuesta = direccionServicio.getBytes();
                byte[] datosCifradosRespuesta = AES.encriptar(datosRespuesta, claveAES, vectorInicialRespuesta);
                salida.writeInt(datosCifradosRespuesta.length);
                salida.write(datosCifradosRespuesta);
                
                byte[] hmacRespuesta = HMAC.generarHMAC(datosCifradosRespuesta, claveHMAC);
                salida.writeInt(hmacRespuesta.length);
                salida.write(hmacRespuesta);
                
                System.out.println("Respuesta del servidor para servicio " + idServicio + ": " + direccionServicio);
                System.out.println("Respuesta enviada al cliente " + socketCliente.getInetAddress() + ": IV=" + bytesToHex(vectorInicialRespuesta) + ", Datos=" + bytesToHex(datosCifradosRespuesta) + ", HMAC=" + bytesToHex(hmacRespuesta));
            }
        } catch (EOFException e) {
            // El cliente cerró la conexión
            System.out.println("Cliente " + socketCliente.getInetAddress() + " cerró la conexión");
        } catch (Exception e) {
            System.err.println("Error al procesar solicitud: " + e.getMessage());
        } finally {
            try {
                socketCliente.close();
                System.out.println("Conexión cerrada con cliente " + socketCliente.getInetAddress());
            } catch (IOException e) {
                System.err.println("Error al cerrar conexión: " + e.getMessage());
            }
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder resultado = new StringBuilder();
        for (byte b : bytes) {
            resultado.append(String.format("%02x", b));
        }
        return resultado.toString();
    }
}