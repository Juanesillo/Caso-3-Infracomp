import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;

public class Cliente {
    private static byte[] kAB1; // Clave para AES
    private static byte[] kAB2; // Clave para HMAC

    public static void main(String[] args) throws Exception {
        Socket socket = new Socket("localhost", 8080);
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

        // Recibir parámetros DH
        int pLen = in.readInt();
        byte[] pBytes = new byte[pLen];
        in.readFully(pBytes);
        int gLen = in.readInt();
        byte[] gBytes = new byte[gLen];
        in.readFully(gBytes);

        BigInteger p = new BigInteger(pBytes);
        BigInteger g = new BigInteger(gBytes);
        DHParameterSpec dhSpec = new DHParameterSpec(p, g);

        // Recibir clave pública del servidor
        int len = in.readInt();
        byte[] serverPublicKeyBytes = new byte[len];
        in.readFully(serverPublicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        PublicKey serverPublicKeyDH = keyFactory.generatePublic(new java.security.spec.X509EncodedKeySpec(serverPublicKeyBytes));

        // Generar y enviar clave pública DH
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKeyDH = keyPair.getPublic();
        PrivateKey privateKeyDH = keyPair.getPrivate();

        out.writeInt(publicKeyDH.getEncoded().length);
        out.write(publicKeyDH.getEncoded());

        // Calcular clave secreta compartida
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKeyDH);
        keyAgree.doPhase(serverPublicKeyDH, true);
        byte[] sharedSecret = keyAgree.generateSecret();

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);
        kAB1 = Arrays.copyOfRange(digest, 0, 32);
        kAB2 = Arrays.copyOfRange(digest, 32, 64);

        // Recibir tabla de servicios
        byte[] ivBytes = new byte[16];
        in.readFully(ivBytes);
        int encryptedLen = in.readInt();
        byte[] encryptedTabla = new byte[encryptedLen];
        in.readFully(encryptedTabla);
        byte[] hmacTabla = new byte[32];
        in.readFully(hmacTabla);

        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec macKey = new SecretKeySpec(kAB2, "HmacSHA256");
        mac.init(macKey);
        byte[] computedHmac = mac.doFinal(encryptedTabla);
        if (!Arrays.equals(hmacTabla, computedHmac)) {
            System.out.println("HMAC inválido en tabla");
            socket.close();
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(kAB1, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] tablaBytes = cipher.doFinal(encryptedTabla);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(tablaBytes));
        Map<Integer, String> tablaServicios = (Map<Integer, String>) ois.readObject();

        System.out.println("Servicios disponibles:");
        for (Map.Entry<Integer, String> entry : tablaServicios.entrySet()) {
            System.out.println("ID: " + entry.getKey() + " -> " + entry.getValue());
        }

        // Enviar solicitud
        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese el ID del servicio: ");
        int serviceId = scanner.nextInt();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeInt(serviceId);
        byte[] requestBytes = baos.toByteArray();

        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] encryptedRequest = cipher.doFinal(requestBytes);
        byte[] hmacRequest = mac.doFinal(encryptedRequest);

        out.write(ivBytes);
        out.writeInt(encryptedRequest.length);
        out.write(encryptedRequest);
        out.write(hmacRequest);

        // Recibir respuesta
        in.readFully(ivBytes);
        encryptedLen = in.readInt();
        byte[] encryptedResponse = new byte[encryptedLen];
        in.readFully(encryptedResponse);
        byte[] hmacResponse = new byte[32];
        in.readFully(hmacResponse);

        if (!Arrays.equals(hmacResponse, mac.doFinal(encryptedResponse))) {
            System.out.println("HMAC inválido en respuesta");
            socket.close();
            return;
        }

        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] responseBytes = cipher.doFinal(encryptedResponse);
        String response = new String(responseBytes);
        System.out.println("Respuesta del servidor: " + response);

        socket.close();
    }
}