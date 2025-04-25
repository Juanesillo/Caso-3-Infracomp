package AlgoritmosCripto;

import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACUtil {
    public static byte[] generateHMAC(byte[] data, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        mac.init(keySpec);
        return mac.doFinal(data);
    }

    public static boolean verifyHMAC(byte[] data, byte[] expected, byte[] key) throws Exception {
        return MessageDigest.isEqual(generateHMAC(data, key), expected);
    }
}