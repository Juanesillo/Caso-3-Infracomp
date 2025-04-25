package AlgoritmosCripto;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;

public class DH {
    private DHParameterSpec parametrosDH;

    public DH(BigInteger p, BigInteger g) {
        this.parametrosDH = new DHParameterSpec(p, g);
    }

    public static DHParameterSpec generarParametros() throws Exception {
        AlgorithmParameterGenerator generadorParametros = AlgorithmParameterGenerator.getInstance("DH");
        generadorParametros.init(1024);
        AlgorithmParameters parametros = generadorParametros.generateParameters();
        return parametros.getParameterSpec(DHParameterSpec.class);
    }

    public KeyPair generarParDeClaves() throws Exception {
        KeyPairGenerator generadorClaves = KeyPairGenerator.getInstance("DH");
        generadorClaves.initialize(parametrosDH);
        return generadorClaves.generateKeyPair();
    }

    public PublicKey decodificarClavePublica(DataInputStream entrada) throws Exception {
        int longitud = entrada.readInt();
        byte[] bytesClave = new byte[longitud];
        entrada.readFully(bytesClave);
        KeyFactory fabricaClaves = KeyFactory.getInstance("DH");
        return fabricaClaves.generatePublic(new X509EncodedKeySpec(bytesClave));
    }

    public void enviarClavePublica(DataOutputStream salida, PublicKey clavePublica) throws Exception {
        byte[] bytesClave = clavePublica.getEncoded();
        salida.writeInt(bytesClave.length);
        salida.write(bytesClave);
    }

    public byte[] calcularSecretoCompartido(PrivateKey clavePrivada, PublicKey clavePublica) throws Exception {
        KeyAgreement acuerdoClaves = KeyAgreement.getInstance("DH");
        acuerdoClaves.init(clavePrivada);
        acuerdoClaves.doPhase(clavePublica, true);
        return acuerdoClaves.generateSecret();
    }

    public static byte[][] generarClavesDeSesion(byte[] secretoCompartido) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(secretoCompartido);
        byte[] claveAES = Arrays.copyOfRange(digest, 0, 32);
        byte[] claveHMAC = Arrays.copyOfRange(digest, 32, 64);
        return new byte[][]{claveAES, claveHMAC};
    }
}