package app.activities;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

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
            System.out.println("encryptedPasswordBase64: " + encryptedPasswordBase64);
            byte[] encryptedPassword = Base64.getDecoder().decode(encryptedPasswordBase64);
            // Decrypt the password
            String password = decryptPassword(encryptedPassword);
            System.out.println("password after decryption: " + password);
            // Validate username and password
            if (authenticateUser(username, password)) {
                out.println("Login successful. Welcome, " + username + "!");
                // If authentication successful, obtain the secret key for the user
                byte[] secretKey = Server.getUserSecretKeys().get(username);
                System.out.println("secretKey: " + secretKey);
                // Encrypt the secret key and send it to the client
                out.println(Base64.getEncoder().encodeToString(encryptSecretKey(secretKey, password)));
            } else {
                out.println("Invalid username or password.");
            }
            
            // Handle client requests
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received from client: " + inputLine);

                // Handle create project command
                if (inputLine.startsWith("create ")) {
                    String projectName = inputLine.substring(7); // Extract project name
                    // if (createProject(projectName, userProjects)) {
                    //     out.println("Project '" + projectName + "' created successfully.");
                    // } else {
                    //     out.println("Failed to create project '" + projectName + "'.");
                    // }
                } 
                // Handle list projects command
                else if (inputLine.equals("list projects")) {
                    //out.println("Your projects: " + userProjects.toString());
                }
                else if (inputLine.startsWith("send ")) {
                    String fileName = inputLine.substring(5);
                    FileHandler fileHandler = new FileHandler("server_data/" + fileName);
                    fileHandler.receiveFile(dataInputStream);
                    out.println(fileName + " has been received by server");
                }
                else if (inputLine.startsWith("download ")) {
                    String fileName = inputLine.substring(9);
                    FileHandler fileHandler = new FileHandler("server_data/" + fileName);
                    fileHandler.sendFile(dataOutputStream);
                }
                else if (inputLine.startsWith("delete ")) {
                    String fileName = inputLine.substring(7);
                    FileHandler fileHandler = new FileHandler("server_data/" + fileName);
                    boolean deleted = fileHandler.deleteFile();
                    if (deleted) {
                        out.println(fileName + " has been deleted.");
                    } else {
                        out.println(fileName + " has not been deleted...either the file does not exist or something else went wrong.");
                    }
                }
                else if (inputLine.equals("list")) {
                    FileHandler fileHandler = new FileHandler("server_data/");
                    String output = fileHandler.listFiles();
                    out.println(output);
                }
                else {
                    // Example of responding to client
                    //out.println("Server received: " + inputLine);
                }
            }
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

    private boolean authenticateUser(String username, String providedPassword) {
        // Retrieve the stored hashed password for the provided username
        byte[] storedPasswordHash = Server.getUserPasswords().get(username);
        if (storedPasswordHash == null) {
            System.out.println("Username not found: " + username);
            return false; // Username not found
        }
    
        // Hash the provided password
        byte[] hashedProvidedPassword = hashPassword(providedPassword);
    
        // Compare the hashed provided password with the stored password hash using a secure comparison method
        return MessageDigest.isEqual(hashedProvidedPassword, storedPasswordHash);
    }

    private byte[] hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // private String decryptPassword(byte[] encryptedPassword) {
    //     // Convert the password string to a byte array
    //     // TODO: change this to not be hard coded for alice's password but rather user input
    //     byte[] passwordBytes = "password123".getBytes(StandardCharsets.UTF_8);
    //     System.out.println("passwordBytes:" + passwordBytes.toString());
        
    //     // Implement password decryption here
    //     System.out.println("here1");
    //     byte[] decryptedPasswordBytes = Server.decryptSecretKey(encryptedPassword, passwordBytes);
    //     System.out.println("decryptedPasswordBytes: " + decryptedPasswordBytes.toString());
        
    //     System.out.println("here2");
    //     // Convert the decrypted byte array back to a string
    //     String decryptedPassword = new String(decryptedPasswordBytes, StandardCharsets.UTF_8);
    //     System.out.println("decryptedPassword: " + decryptedPassword);
        
    //     return decryptedPassword;
    // }

    private String decryptPassword(byte[] encryptedPassword) {
        // Use the server's preconfigured password for decryption
        String serverPassword = "your_server_password_here";
        byte[] passwordBytes = serverPassword.getBytes(StandardCharsets.UTF_8);
        System.out.println("Password bytes: " + Arrays.toString(passwordBytes));
    
        // Implement password decryption here
        System.out.println("Decryption started...");
        byte[] decryptedPasswordBytes = Server.decryptSecretKey(encryptedPassword, passwordBytes);
        System.out.println("Decrypted password bytes: " + Arrays.toString(decryptedPasswordBytes));
    
        // Convert the decrypted byte array back to a string
        String decryptedPassword = new String(decryptedPasswordBytes, StandardCharsets.UTF_8);
        System.out.println("Decrypted password: " + decryptedPassword);
    
        return decryptedPassword;
    }
    
    

    private byte[] encryptSecretKey(byte[] secretKey, String password) {
        return Server.encryptSecretKey(secretKey, Client.encryptPassword(password));
    }
}
