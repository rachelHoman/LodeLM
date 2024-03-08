package app.activities;
import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import app.utils.FileHandler;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;

    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void run() {
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            // Receive username from client
            String username = in.readLine();
            // Receive encrypted password from client
            String encryptedPasswordBase64 = in.readLine();
            // byte[] encryptedPassword = Base64.getDecoder().decode(encryptedPasswordBase64);
            byte[] password = Base64.getDecoder().decode(encryptedPasswordBase64);
            // Decrypt the password
            // String password = decryptPassword(encryptedPassword);
            // Validate username and password
            if (authenticateUser(username, password)) {
                out.println("Login successful. Welcome, " + username + "!");
                // If authentication successful, obtain the secret key for the user
                byte[] secretKey = Server.getUserSecretKeys().get(username);
                // Encrypt the secret key and send it to the client
                out.println(Base64.getEncoder().encodeToString(encryptSecretKey(secretKey, password)));
            } else {
                out.println("Invalid username or password.");
            }
            
            // Handle client requests
            // Your existing code here...
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                // Close connections
                in.close();
                out.close();
                dataInputStream.close();
                dataOutputStream.close();
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean authenticateUser(String username, byte[] password) {
        // Validate username and password using server's logic
        return Server.verifyPassword(password, Server.getUserPasswords().get(username));
    }

    private String decryptPassword(byte[] encryptedPassword) {
        // Implement password decryption here
        return new String(encryptedPassword); // For demonstration, return decrypted password as string
    }

    private byte[] encryptSecretKey(byte[] secretKey, byte[] password) {
        return Server.encryptSecretKey(secretKey, password);
    }
}

