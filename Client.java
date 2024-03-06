import java.io.*;
import java.net.*;

public class Client {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

            // Prompt the user for username
            System.out.print("Enter your username: ");
            String username = userInput.readLine();
            out.println(username); // Send username to server

            // Prompt the user for password
            System.out.print("Enter your password: ");
            String password = userInput.readLine();
            out.println(password); // Send password to server

            // Receive response from server
            String response;
            while ((response = in.readLine()) != null) {
                System.out.println(response);
                break; // Exit loop after receiving response
            }

            // Close connections
            userInput.close();
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
