import java.util.Scanner;

public class Lab {
    public static void main(String[] args) {
        

        Scanner scanner = new Scanner(System.in);
        System.out.print("Ingrese cuántos clientes desea lanzar: ");
        int numClientes = scanner.nextInt();
        scanner.close();

        for (int i = 0; i < numClientes; i++) {
            final int clienteId = i + 1; // ID de servicio simulado
            new Thread(() -> {
                Cliente.ejecutarCliente(clienteId % 2 + 1); // Alterna entre servicio 1 y 2
            }).start();
        }
    }
}
