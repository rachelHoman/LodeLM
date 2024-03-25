package activities;

import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import utils.FileHandler;

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
            byte[] password = Base64.getDecoder().decode(encryptedPasswordBase64);

            System.out.println(System.getProperty("user.dir"));

            
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
            // TODO: give the users a list of things they can do on the server to prompt them
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received from client: " + inputLine);

                // Handle create project command
                if (inputLine.startsWith("create ")) {
                    String projectName = inputLine.substring(7); // Extract project name
                    // TODO: don't need this with databse -- delete
                } 
                // Handle list projects command
                else if (inputLine.equals("list projects")) {
                    // TODO: don't need this with databse --> delete
                    
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

    private boolean authenticateUser(String username, byte[] password) {
        // Validate username and password using server's logic
        return Server.verifyPassword(password, Server.getUserPasswords().get(username));
    }

    private String decryptPassword(byte[] encryptedPassword) {
        // Implement password decryption here
        // For demonstration, return decrypted password as string
        return new String(encryptedPassword); 
    }

    private byte[] encryptSecretKey(byte[] secretKey, byte[] password) {
        return Server.encryptSecretKey(secretKey, password);
    }
}