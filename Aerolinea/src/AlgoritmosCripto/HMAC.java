package AlgoritmosCripto;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMAC {
    public static byte[] generarHMAC(byte[] datos, byte[] clave) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec especificacionClave = new SecretKeySpec(clave, "HmacSHA256");
        mac.init(especificacionClave);
        return mac.doFinal(datos);
    }

    public static boolean verificarHMAC(byte[] datos, byte[] esperado, byte[] clave) throws Exception {
        return MessageDigest.isEqual(generarHMAC(datos, clave), esperado);
    }
}