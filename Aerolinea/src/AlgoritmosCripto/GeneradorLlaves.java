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

public class GeneradorLlaves {
    private static final String ALGORITMO = "RSA";

    public static void main(String[] args) {
        try {
            System.out.println("Iniciando creación de llaves...");
            Thread.sleep(1000);

            KeyPairGenerator generador = KeyPairGenerator.getInstance(ALGORITMO);
            generador.initialize(1024);
            KeyPair parLlaves = generador.generateKeyPair();

            System.out.println("Llaves generadas de manera exitosa");
            Thread.sleep(1000);

            PublicKey llavePublica = parLlaves.getPublic();
            PrivateKey llavePrivada = parLlaves.getPrivate();

            File directorio = new File("Llaves");
            if (!directorio.exists()) {
                directorio.mkdirs();
            }

            System.out.println("Almacenando llaves en archivos...");
            try (FileOutputStream archivoPublico = new FileOutputStream("Llaves/LlavePublica.txt");
                 ObjectOutputStream oos = new ObjectOutputStream(archivoPublico)) {
                oos.writeObject(llavePublica);
            }

            try (FileOutputStream archivoPrivado = new FileOutputStream("Llaves/LlavePrivada.secret");
                 ObjectOutputStream oos1 = new ObjectOutputStream(archivoPrivado)) {
                oos1.writeObject(llavePrivada);
            }

            System.out.println("Almacenamiento exitoso");
        } catch (NoSuchAlgorithmException | IOException | InterruptedException e) {
            System.err.println("Error durante la generación o almacenamiento de llaves: " + e.getMessage());
        }
    }
}