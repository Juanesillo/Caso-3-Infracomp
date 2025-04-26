package AlgoritmosCripto;

import java.io.*;
import java.security.*;

public class RSA {
    public static byte[] firmar(byte[] datos, PrivateKey llavePrivada) throws Exception {
        Signature firma = Signature.getInstance("SHA256withRSA");
        firma.initSign(llavePrivada);
        firma.update(datos);
        return firma.sign();
    }

    public static boolean verificar(byte[] datos, byte[] firma, PublicKey llavePublica) throws Exception {
        Signature verificacion = Signature.getInstance("SHA256withRSA");
        verificacion.initVerify(llavePublica);
        verificacion.update(datos);
        return verificacion.verify(firma);
    }

    public static PublicKey cargarLlavePublica(String ruta) throws Exception {
        FileInputStream fis = new FileInputStream(ruta);
        ObjectInputStream ois = new ObjectInputStream(fis);
        PublicKey llavePublica = (PublicKey) ois.readObject();
        ois.close();
        return llavePublica;
    }

    public static PrivateKey cargarLlavePrivada(String ruta) throws Exception {
        FileInputStream fis = new FileInputStream(ruta);
        ObjectInputStream ois = new ObjectInputStream(fis);
        PrivateKey llavePrivada = (PrivateKey) ois.readObject();
        ois.close();
        return llavePrivada;
    }
}