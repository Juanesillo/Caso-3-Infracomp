package Comunicacion;
import AlgoritmosCripto.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.crypto.spec.DHParameterSpec;

public class Servidor {
    private static Map<Integer, String> tablaServicios = new HashMap<>();
    private static PrivateKey privateKey;
    private static long totalSignTime = 0;
    private static long totalEncryptTime = 0;
    private static long totalVerifyTime = 0;
    private static int operationCount = 0;

    public static void main(String[] args) throws Exception {
        // Cargar la llave privada usando RSAUtil
        privateKey = RSAUtil.cargarLlavePrivada("Keys/PrivateKey.secret");

        // Inicializar tabla de servicios
        tablaServicios.put(1, "192.168.1.1:9001");
        tablaServicios.put(2, "192.168.1.2:9002");

        try (ServerSocket serverSocket = new ServerSocket(8080)) {
            System.out.println("Servidor iniciado en puerto 8080...");
            while (true) {
                Socket clientSocket = serverSocket.accept();
                clientSocket.setSoTimeout(10000); // Timeout de 10 segundos
                System.out.println("Cliente conectado: " + clientSocket.getInetAddress());
                new Thread(() -> manejarCliente(clientSocket)).start();
            }
        } catch (Exception e) {
            System.out.println("Fallo en iniciar el servidor: " + e.getMessage());
        }
    }

    private static void manejarCliente(Socket socket) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Generar y enviar parámetros DH
            DHParameterSpec dhSpec = DHUtil.generateParams();
            BigInteger p = dhSpec.getP();
            BigInteger g = dhSpec.getG();
            out.writeInt(p.toByteArray().length);
            out.write(p.toByteArray());
            out.writeInt(g.toByteArray().length);
            out.write(g.toByteArray());
            out.flush();

            // Generar claves DH
            DHUtil dhUtil = new DHUtil(p, g);
            KeyPair keyPair = dhUtil.generateKeyPair();
            PublicKey publicKeyDH = keyPair.getPublic();
            PrivateKey privateKeyDH = keyPair.getPrivate();
            dhUtil.sendPublicKey(out, publicKeyDH);

            // Recibir clave pública del cliente
            PublicKey clientPublicKeyDH = dhUtil.decodePublicKey(in);

            // Calcular secreto compartido
            byte[] sharedSecret = dhUtil.computeSharedSecret(privateKeyDH, clientPublicKeyDH);

            // Generar claves de sesión
            byte[][] sessionKeys = DHUtil.generateSessionKeys(sharedSecret);
            byte[] kAB1 = sessionKeys[0]; // Clave para AES
            byte[] kAB2 = sessionKeys[1]; // Clave para HMAC

            // Serializar la tabla de servicios
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(tablaServicios);
            byte[] tablaBytes = baos.toByteArray();

            // Firmar la tabla con RSA
            long startSign = System.nanoTime();
            byte[] firma = RSAUtil.sign(tablaBytes, privateKey);
            long endSign = System.nanoTime();
            synchronized (Servidor.class) {
                totalSignTime += (endSign - startSign);
                operationCount++;
            }

            // Enviar la tabla y la firma
            out.writeInt(tablaBytes.length);
            out.write(tablaBytes);
            out.writeInt(firma.length);
            out.write(firma);
            out.flush();

            // Enviar IV, tabla cifrada y HMAC
            byte[] ivBytes = AESUtil.generateIV();
            long startEncrypt = System.nanoTime();
            byte[] encryptedTabla = AESUtil.encrypt(tablaBytes, kAB1, ivBytes);
            long endEncrypt = System.nanoTime();
            synchronized (Servidor.class) {
                totalEncryptTime += (endEncrypt - startEncrypt);
            }

            byte[] hmacTabla = HMACUtil.generateHMAC(encryptedTabla, kAB2);

            out.write(ivBytes);
            out.writeInt(encryptedTabla.length);
            out.write(encryptedTabla);
            out.write(hmacTabla);
            out.flush();

            // Delegar la solicitud al ServidorDelegado
            ServidorDelegado delegado = new ServidorDelegado(socket, tablaServicios, kAB1, kAB2);
            new Thread(delegado).start();

        } catch (Exception e) {
            System.err.println("Error al manejar cliente " + socket.getInetAddress() + ": " + e.getMessage());
            try {
                socket.close();
            } catch (IOException ex) {
                System.err.println("Error al cerrar el socket: " + ex.getMessage());
            }
        }
    }

    public static synchronized void addVerificationTime(long time) {
        totalVerifyTime += time;
    }

    public static synchronized double getAverageSignTime() {
        return operationCount > 0 ? totalSignTime / (double) operationCount / 1_000_000.0 : 0;
    }

    public static synchronized double getAverageEncryptTime() {
        return operationCount > 0 ? totalEncryptTime / (double) operationCount / 1_000_000.0 : 0;
    }

    public static synchronized double getAverageVerifyTime() {
        return operationCount > 0 ? totalVerifyTime / (double) operationCount / 1_000_000.0 : 0;
    }

    public static synchronized void resetTimes() {
        totalSignTime = 0;
        totalEncryptTime = 0;
        totalVerifyTime = 0;
        operationCount = 0;
    }
}