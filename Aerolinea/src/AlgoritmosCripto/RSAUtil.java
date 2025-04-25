package AlgoritmosCripto;

import java.io.*;
import java.security.*;

public class RSAUtil {
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(byte[] data, byte[] sig, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sig);
    }

    public static PublicKey cargarLlavePublica(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        ObjectInputStream ois = new ObjectInputStream(fis);
        PublicKey publicKey = (PublicKey) ois.readObject();
        ois.close();
        return publicKey;
    }

    public static PrivateKey cargarLlavePrivada(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        ObjectInputStream ois = new ObjectInputStream(fis);
        PrivateKey privateKey = (PrivateKey) ois.readObject();
        ois.close();
        return privateKey;
    }
}