package AlgoritmosCripto;

import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.*;

public class AES {
    public static byte[] generarIV() {
        byte[] iv = new byte[16];
        SecureRandom aleatorio = new SecureRandom();
        aleatorio.nextBytes(iv);
        return iv;
    }

    public static byte[] encriptar(byte[] datos, byte[] clave, byte[] iv) throws Exception {
        Cipher cifrador = inicializarCifrador(Cipher.ENCRYPT_MODE, clave, iv);
        return cifrador.doFinal(datos);
    }

    public static byte[] desencriptar(byte[] datosEncriptados, byte[] clave, byte[] iv) throws Exception {
        Cipher cifrador = inicializarCifrador(Cipher.DECRYPT_MODE, clave, iv);
        return cifrador.doFinal(datosEncriptados);
    }

    public static Cipher inicializarCifrador(int modo, byte[] clave, byte[] iv) throws Exception {
        SecretKeySpec especificacionClave = new SecretKeySpec(clave, "AES");
        IvParameterSpec especificacionIV = new IvParameterSpec(iv);
        Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifrador.init(modo, especificacionClave, especificacionIV);
        return cifrador;
    }
}