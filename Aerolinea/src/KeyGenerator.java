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

        // Crear con antelación las llaves Publica y Privada 
        // Para almacenarlas en dos archivos diferentes

        // Condiciones de uso => El servidor conoce ambas llaves mientras que el cliente solo conoce la llave Publica 
        try {

            System.out.println("Iniciando Creación de llaves...");
            Thread.sleep(1000);


            // Se crea el generador de llaves empleando el algoritmo RSA 
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
            // Tamaño explícito de 1024 bits para cada llave =>  por seguridad se deja en 1024  
            // Entre mayor sea el número de bits más segura sera la clave
            generator.initialize(1024); 
            KeyPair keyPair = generator.generateKeyPair();
    
            System.out.println("Llaves generadas de manera exitosa");
            Thread.sleep(1000);

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            // sino existe el directorio lo crea para poder almacenar los archivos de las llaves
            File directorio = new File("Keys");
            if (!directorio.exists()) {
                directorio.mkdirs();
            }
            // Se crean y se almacenan los archivos dentro del directorio KEYS
            
            System.out.println("Almacenando llaves en Archivos...");
            // Llave Pública
            try (FileOutputStream publicFile = new FileOutputStream("Keys/PublicKey.txt");
                 ObjectOutputStream oos = new ObjectOutputStream(publicFile)) {
                oos.writeObject(publicKey);
            }

            // Llave Privada
            try (FileOutputStream privateFile = new FileOutputStream("Keys/PrivateKey.secret");
                 ObjectOutputStream oos1 = new ObjectOutputStream(privateFile)) {
                oos1.writeObject(privateKey);
            }

            System.out.println("Almacenamiento exitoso");



            // Catcht de posibles errores durante el almacenamiento 
        } catch (NoSuchAlgorithmException | IOException | InterruptedException e) {
            System.err.println("Error durante la generación o almacenamiento de llaves: " + e.getMessage());
        }
    }
}