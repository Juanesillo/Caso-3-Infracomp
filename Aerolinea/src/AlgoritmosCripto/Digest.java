package AlgoritmosCripto;

import java.security.*;
import java.util.Arrays;

public class Digest {
    public static byte[][] derivarClaves(byte[] secretoCompartido) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(secretoCompartido);
        byte[] claveAES = Arrays.copyOfRange(digest, 0, 32);
        byte[] claveHMAC = Arrays.copyOfRange(digest, 32, 64);
        return new byte[][]{claveAES, claveHMAC};
    }
}