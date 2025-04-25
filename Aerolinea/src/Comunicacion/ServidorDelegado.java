package Comunicacion;

import AlgoritmosCripto.*;
import java.io.*;
import java.net.*;
import java.util.Map;

public class ServidorDelegado implements Runnable {
    private Socket socket;
    private Map<Integer, String> tablaServicios;
    private byte[] kAB1; // Clave para AES
    private byte[] kAB2; // Clave para HMAC

    public ServidorDelegado(Socket socket, Map<Integer, String> tablaServicios, byte[] kAB1, byte[] kAB2) {
        this.socket = socket;
        this.tablaServicios = tablaServicios;
        this.kAB1 = kAB1;
        this.kAB2 = kAB2;
    }

    @Override
    public void run() {
        DataOutputStream out = null;
        DataInputStream in = null;
        try {
            out = new DataOutputStream(socket.getOutputStream());
            in = new DataInputStream(socket.getInputStream());

            // Recibir solicitud
            byte[] ivBytes = new byte[16];
            in.readFully(ivBytes);
            System.out.println("IV recibido para cliente " + socket.getInetAddress());
            int encryptedLen = in.readInt();
            if (encryptedLen <= 0) throw new IOException("Longitud de solicitud cifrada inválida: " + encryptedLen);
            byte[] encryptedRequest = new byte[encryptedLen];
            in.readFully(encryptedRequest);
            System.out.println("Solicitud cifrada recibida (" + encryptedLen + " bytes) para cliente " + socket.getInetAddress());
            byte[] receivedHmac = new byte[32];
            in.readFully(receivedHmac);
            System.out.println("HMAC recibido para cliente " + socket.getInetAddress());

            // Verificar HMAC
            long startVerify = System.nanoTime();
            boolean hmacValid = HMACUtil.verifyHMAC(encryptedRequest, receivedHmac, kAB2);
            long endVerify = System.nanoTime();
            Servidor.addVerificationTime(endVerify - startVerify);

            if (!hmacValid) {
                System.out.println("HMAC inválido en solicitud del cliente " + socket.getInetAddress() + ". Datos recibidos: " + bytesToHex(encryptedRequest) + ", HMAC esperado: " + bytesToHex(HMACUtil.generateHMAC(encryptedRequest, kAB2)) + ", HMAC recibido: " + bytesToHex(receivedHmac));
                return;
            }

            // Descifrar solicitud
            byte[] requestBytes = AESUtil.decrypt(encryptedRequest, kAB1, ivBytes);
            int serviceId = new DataInputStream(new ByteArrayInputStream(requestBytes)).readInt();
            System.out.println("Cliente " + socket.getInetAddress() + " solicitó el servicio ID: " + serviceId);

            // Enviar respuesta
            String response = tablaServicios.getOrDefault(serviceId, "-1:-1");
            System.out.println("Enviando respuesta al cliente " + socket.getInetAddress() + ": " + response);
            byte[] responseBytes = response.getBytes();
            ivBytes = AESUtil.generateIV();
            byte[] encryptedResponse = AESUtil.encrypt(responseBytes, kAB1, ivBytes);
            byte[] hmacResponse = HMACUtil.generateHMAC(encryptedResponse, kAB2);

            out.write(ivBytes);
            out.writeInt(encryptedResponse.length);
            out.write(encryptedResponse);
            out.write(hmacResponse);
            out.flush();
            System.out.println("Respuesta enviada al cliente " + socket.getInetAddress() + ": IV=" + bytesToHex(ivBytes) + ", Datos=" + bytesToHex(encryptedResponse) + ", HMAC=" + bytesToHex(hmacResponse));

        } catch (Exception e) {
            System.err.println("Error en ServidorDelegado para cliente " + socket.getInetAddress() + ": " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                socket.close();
                System.out.println("Conexión cerrada con cliente " + socket.getInetAddress());
            } catch (IOException e) {
                System.err.println("Error al cerrar el socket: " + e.getMessage());
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}