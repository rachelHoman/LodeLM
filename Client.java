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

            // Send username to the server
            out.println(username);

            // Receive and print the greeting message from the server
            String greeting = in.readLine();
            System.out.println(greeting);

            String userMessage;
            while ((userMessage = userInput.readLine()) != null) {
                out.println(userMessage);

                // Exit loop if user types 'exit'
                if (userMessage.equalsIgnoreCase("exit")) {
                    break;
                }

                // Print server responses
                String response;
                while ((response = in.readLine()) != null) {
                    System.out.println(response);

                    // Break out of inner loop to return to waiting for user input
                    break;
                }
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
