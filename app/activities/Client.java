package app.activities;

import java.io.*;
import java.net.*;
import app.utils.*;

public class Client {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int SERVER_PORT = 12345;

    public static void main(String[] args) {
        try {
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            System.out.println("Connected to Server");

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); //server input stream
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in)); //user input stream

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
                
                if (userMessage.equals("send file")) {
                    FileHandler fileHandler = new FileHandler("client_data/file1.txt");
                    fileHandler.sendFile(dataOutputStream);
                }

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
