import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Servidor {
    // ASignación de la tabla IP -> Servicios
    private static Map<Integer, String> tablaServicios = new HashMap<>();

    // Se definen las claves 

    
    private static byte[] kAB1; // Clave para AES
    private static byte[] kAB2; // Clave para HMAC


    public static void main(String[] args) throws Exception {
        // Inicializar tabla de servicios
        tablaServicios.put(1, "192.168.1.1:9001");
        tablaServicios.put(2, "192.168.1.2:9002");

        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("Servidor iniciado en puerto 8080...");
        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado: " + clientSocket.getInetAddress());
            new Thread(() -> manejarCliente(clientSocket)).start();
        }
    }

    private static void manejarCliente(Socket socket) {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // Paso 1: Intercambio de claves Diffie-Hellman
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(1024);
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            keyGen.initialize(dhSpec);
            KeyPair keyPair = keyGen.generateKeyPair();
            PublicKey publicKeyDH = keyPair.getPublic();
            PrivateKey privateKeyDH = keyPair.getPrivate();

            // Enviar clave pública DH al cliente
            byte[] publicKeyBytes = publicKeyDH.getEncoded();
            out.writeInt(publicKeyBytes.length);
            out.write(publicKeyBytes);

            // Recibir clave pública DH del cliente
            int len = in.readInt();
            byte[] clientPublicKeyBytes = new byte[len];
            in.readFully(clientPublicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey clientPublicKeyDH = keyFactory.generatePublic(new X509EncodedKeySpec(clientPublicKeyBytes));

            // Calcular clave secreta compartida
            KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
            keyAgree.init(privateKeyDH);
            keyAgree.doPhase(clientPublicKeyDH, true);
            byte[] sharedSecret = keyAgree.generateSecret();

            // Derivar claves simétricas (AES y HMAC)
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(sharedSecret);
            kAB1 = Arrays.copyOfRange(digest, 0, 32); // 256 bits para AES
            kAB2 = Arrays.copyOfRange(digest, 32, 64); // 256 bits para HMAC

            // Paso 2: Enviar tabla de servicios cifrada
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(tablaServicios);
            byte[] tablaBytes = baos.toByteArray();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec key = new SecretKeySpec(kAB1, "AES");
            IvParameterSpec iv = new IvParameterSpec(new byte[16]); // IV fijo para simplicidad
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedTabla = cipher.doFinal(tablaBytes);

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec macKey = new SecretKeySpec(kAB2, "HmacSHA256");
            mac.init(macKey);
            byte[] hmacTabla = mac.doFinal(encryptedTabla);

            // Enviar IV, tabla cifrada y HMAC
            out.write(iv.getIV());
            out.writeInt(encryptedTabla.length);
            out.write(encryptedTabla);
            out.write(hmacTabla);

            // Paso 3: Recibir solicitud del cliente
            byte[] ivBytes = new byte[16];
            in.readFully(ivBytes);
            int encryptedLen = in.readInt();
            byte[] encryptedRequest = new byte[encryptedLen];
            in.readFully(encryptedRequest);
            byte[] receivedHmac = new byte[32];
            in.readFully(receivedHmac);

            // Verificar HMAC
            byte[] computedHmac = mac.doFinal(encryptedRequest);
            if (!Arrays.equals(receivedHmac, computedHmac)) {
                System.out.println("HMAC inválido");
                socket.close();
                return;
            }

            // Descifrar solicitud
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
            byte[] requestBytes = cipher.doFinal(encryptedRequest);
            int serviceId = new DataInputStream(new ByteArrayInputStream(requestBytes)).readInt();

            // Paso 4: Enviar respuesta
            String response = tablaServicios.getOrDefault(serviceId, "-1:-1");
            byte[] responseBytes = response.getBytes();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedResponse = cipher.doFinal(responseBytes);
            byte[] hmacResponse = mac.doFinal(encryptedResponse);

            out.write(iv.getIV());
            out.writeInt(encryptedResponse.length);
            out.write(encryptedResponse);
            out.write(hmacResponse);

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}