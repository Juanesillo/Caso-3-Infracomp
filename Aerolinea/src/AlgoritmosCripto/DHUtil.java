package AlgoritmosCripto;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;

public class DHUtil {
    private DHParameterSpec dhSpec;

    public DHUtil(BigInteger p, BigInteger g) {
        this.dhSpec = new DHParameterSpec(p, g);
    }

    public static DHParameterSpec generateParams() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        return params.getParameterSpec(DHParameterSpec.class);
    }

    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhSpec);
        return keyGen.generateKeyPair();
    }

    public PublicKey decodePublicKey(DataInputStream in) throws Exception {
        int len = in.readInt();
        byte[] keyBytes = new byte[len];
        in.readFully(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public void sendPublicKey(DataOutputStream out, PublicKey publicKey) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        out.writeInt(keyBytes.length);
        out.write(keyBytes);
    }

    public byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH");
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret();
    }

    public static byte[][] generateSessionKeys(byte[] sharedSecret) throws Exception {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(sharedSecret);
        byte[] aesKey = Arrays.copyOfRange(digest, 0, 32);
        byte[] hmacKey = Arrays.copyOfRange(digest, 32, 64);
        return new byte[][]{aesKey, hmacKey};
    }
}