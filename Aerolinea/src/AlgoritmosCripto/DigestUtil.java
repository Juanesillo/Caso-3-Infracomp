package AlgoritmosCripto;

import java.security.*;
import java.util.Arrays;

public class DigestUtil {
    public static byte[][] deriveKeys(byte[] sharedSecret) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);
        byte[] aesKey = Arrays.copyOfRange(digest, 0, 32);
        byte[] hmacKey = Arrays.copyOfRange(digest, 32, 64);
        return new byte[][]{aesKey, hmacKey};
    }
}