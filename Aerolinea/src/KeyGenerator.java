import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyGenerator  {

    
    // Esta clase solo se encarga de generar las llaves 
    // publica  y privada por adelantado 


    // Se define el algoritmo RSA empleado en el laboratorio

    private final static String ALGORITMO= "RSA";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InterruptedException {

        // se crea un archivo ejecutable ya que es el primero en iniciar


    System.out.println("Iniciando Creacion de llaves... \n");

    Thread.sleep(1000);

    KeyPairGenerator generator= KeyPairGenerator.getInstance(ALGORITMO);
    
    KeyPair keyPair= generator.generateKeyPair();


    // Generar las llaves 

    System.out.println(" Llaves generadas de manera exitosa ");
    Thread.sleep(1000);
    PublicKey publicKey= keyPair.getPublic();
    PrivateKey privateKey= keyPair.getPrivate();

    File carpeta = new File("Keys");
        if (!carpeta.exists()) {
             carpeta.mkdirs();
            }   
    // Almacenar las llaves en dos archivos 
    System.out.println("Almacenando llaves en Archivos...");
        // Llave Publica
        FileOutputStream publicFile= new FileOutputStream("Keys/PublicKey.txt");
        ObjectOutputStream oos= new ObjectOutputStream(publicFile);

        oos.writeObject(publicKey);
        oos.close();

        // Llave Privada
        FileOutputStream privateFile= new FileOutputStream("Keys/PrivateKey.secret");
        ObjectOutputStream oos1= new ObjectOutputStream(privateFile);

        oos1.writeObject(privateKey);
        oos1.close();
        
    System.out.println("Almacenamiento exitoso");

        
    }



    


}
