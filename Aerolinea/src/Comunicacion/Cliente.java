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
}