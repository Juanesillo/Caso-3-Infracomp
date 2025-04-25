package Comunicacion;
import AlgoritmosCripto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;

public class Cliente {
    private static byte[] kAB1; // Clave para AES
    private static byte[] kAB2; // Clave para HMAC
    private static PublicKey publicKey; // Llave pública RSA

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese el ID del servicio (1 o 2): ");
        int serviceId = scanner.nextInt();
        scanner.close();
        ejecutarCliente(serviceId);
    }

    public static void ejecutarCliente(int serviceId) throws Exception {
        Socket socket = null;
        try {
            socket = new Socket("localhost", 8080);
            socket.setSoTimeout(10000); // Timeout de 10 segundos para evitar bloqueos
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Cargar la llave pública usando RSAUtil
            publicKey = RSAUtil.cargarLlavePublica("Keys/PublicKey.txt");

            // Recibir parámetros DH
            int pLen = in.readInt();
            if (pLen <= 0) throw new IOException("Longitud de p inválida");
            byte[] pBytes = new byte[pLen];
            in.readFully(pBytes);
            int gLen = in.readInt();
            if (gLen <= 0) throw new IOException("Longitud de g inválida");
            byte[] gBytes = new byte[gLen];
            in.readFully(gBytes);

            BigInteger p = new BigInteger(pBytes);
            BigInteger g = new BigInteger(gBytes);

            // Usar DHUtil para generar claves DH y calcular secreto compartido
            DHUtil dhUtil = new DHUtil(p, g);
            PublicKey serverPublicKeyDH = dhUtil.decodePublicKey(in);
            KeyPair keyPair = dhUtil.generateKeyPair();
            dhUtil.sendPublicKey(out, keyPair.getPublic());
            byte[] sharedSecret = dhUtil.computeSharedSecret(keyPair.getPrivate(), serverPublicKeyDH);

            // Generar claves de sesión usando DHUtil
            byte[][] sessionKeys = DHUtil.generateSessionKeys(sharedSecret);
            kAB1 = sessionKeys[0]; // Clave para AES
            kAB2 = sessionKeys[1]; // Clave para HMAC

            // Recibir tabla y firma
            int tablaLen = in.readInt();
            if (tablaLen <= 0) throw new IOException("Longitud de tabla inválida");
            byte[] tablaBytes = new byte[tablaLen];
            in.readFully(tablaBytes);
            int firmaLen = in.readInt();
            if (firmaLen <= 0) throw new IOException("Longitud de firma inválida");
            byte[] firma = new byte[firmaLen];
            in.readFully(firma);

            // Verificar firma usando RSAUtil
            if (!RSAUtil.verify(tablaBytes, firma, publicKey)) {
                System.out.println("Firma inválida. No se puede confiar en la tabla.");
                return;
            }

            // Deserializar la tabla
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
            Map<Integer, String> tablaServicios = (Map<Integer, String>) ois.readObject();
            System.out.println("Servicios disponibles:");
            for (Map.Entry<Integer, String> entry : tablaServicios.entrySet()) {
                System.out.println("ID: " + entry.getKey() + " -> " + entry.getValue());
            }

            // Recibir IV, tabla cifrada y HMAC
            byte[] ivBytes = new byte[16];
            in.readFully(ivBytes);
            int encryptedLen = in.readInt();
            if (encryptedLen <= 0) throw new IOException("Longitud de tabla cifrada inválida");
            byte[] encryptedTabla = new byte[encryptedLen];
            in.readFully(encryptedTabla);
            byte[] hmacTabla = new byte[32];
            in.readFully(hmacTabla);

            // Verificar HMAC usando HMACUtil
            if (!HMACUtil.verifyHMAC(encryptedTabla, hmacTabla, kAB2)) {
                System.out.println("HMAC inválido en tabla");
                return;
            }

            // Descifrar tabla usando AESUtil
            byte[] decryptedTabla = AESUtil.decrypt(encryptedTabla, kAB1, ivBytes);

            // Enviar solicitud con el serviceId proporcionado
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeInt(serviceId);
            byte[] requestBytes = baos.toByteArray();

            // Cifrar solicitud y generar HMAC
            ivBytes = AESUtil.generateIV();
            byte[] encryptedRequest = AESUtil.encrypt(requestBytes, kAB1, ivBytes);
            byte[] hmacRequest = HMACUtil.generateHMAC(encryptedRequest, kAB2);

            out.write(ivBytes);
            out.writeInt(encryptedRequest.length);
            out.write(encryptedRequest);
            out.write(hmacRequest);
            out.flush();

            // Recibir respuesta
            in.readFully(ivBytes);
            encryptedLen = in.readInt();
            if (encryptedLen <= 0) throw new IOException("Longitud de respuesta cifrada inválida");
            byte[] encryptedResponse = new byte[encryptedLen];
            in.readFully(encryptedResponse);
            byte[] hmacResponse = new byte[32];
            in.readFully(hmacResponse);

            // Verificar HMAC y descifrar respuesta
            if (!HMACUtil.verifyHMAC(encryptedResponse, hmacResponse, kAB2)) {
                System.out.println("HMAC inválido en respuesta");
                return;
            }

            byte[] responseBytes = AESUtil.decrypt(encryptedResponse, kAB1, ivBytes);
            String response = new String(responseBytes);
            System.out.println("Respuesta del servidor para servicio " + serviceId + ": " + response);

        } catch (Exception e) {
            System.err.println("Error en el cliente: " + e.getMessage());
        } finally {
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println("Error al cerrar el socket del cliente: " + e.getMessage());
                }
            }
        }
    }
}