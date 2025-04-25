package AlgoritmosCripto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyGenerator {
    private static final String ALGORITMO = "RSA";

    public static void main(String[] args) {
        try {
            System.out.println("Iniciando Creación de llaves...");
            Thread.sleep(1000);

            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
            generator.initialize(1024);
            KeyPair keyPair = generator.generateKeyPair();

            System.out.println("Llaves generadas de manera exitosa");
            Thread.sleep(1000);

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            File directorio = new File("Keys");
            if (!directorio.exists()) {
                directorio.mkdirs();
            }

            System.out.println("Almacenando llaves en Archivos...");
            try (FileOutputStream publicFile = new FileOutputStream("Keys/PublicKey.txt");
                 ObjectOutputStream oos = new ObjectOutputStream(publicFile)) {
                oos.writeObject(publicKey);
            }

            try (FileOutputStream privateFile = new FileOutputStream("Keys/PrivateKey.secret");
                 ObjectOutputStream oos1 = new ObjectOutputStream(privateFile)) {
                oos1.writeObject(privateKey);
            }

            System.out.println("Almacenamiento exitoso");
        } catch (NoSuchAlgorithmException | IOException | InterruptedException e) {
            System.err.println("Error durante la generación o almacenamiento de llaves: " + e.getMessage());
        }
    }
}