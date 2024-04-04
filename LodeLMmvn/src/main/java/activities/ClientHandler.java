package activities;

import java.io.*;
import java.net.*;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import java.util.Arrays;
import utils.*;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;

    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    DatabHandler dbhandler = new DatabHandler();

    public void run() {
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            // Receive login or create account signal from client
            String action = in.readLine();

            if (action.equals("createAccount")) {
                // Receive username from client
                String username = in.readLine();

                // Receive encrypted password from client
                String encryptedPasswordBase64 = in.readLine();
                // Ensure proper padding by adding '=' characters if necessary
                int padding = encryptedPasswordBase64.length() % 4;
                if (padding > 0) {
                    encryptedPasswordBase64 += "====".substring(padding);
                }
                byte[] password = Base64.getDecoder().decode(encryptedPasswordBase64);
                // Create account and store credentials
                createAccount(username, password);
                out.println("Account creation successful. Proceeding with connection...");
            } else {
                // Receive username from client
                String username = in.readLine();

                // Receive encrypted password from client
                String encryptedPasswordBase64 = in.readLine();
                // Ensure proper padding by adding '=' characters if necessary
                int padding = encryptedPasswordBase64.length() % 4;
                if (padding > 0) {
                    encryptedPasswordBase64 += "====".substring(padding);
                }
                byte[] password = Base64.getDecoder().decode(encryptedPasswordBase64);

                // Validate username and password
                if (authenticateUser(username, password)) {
                    // If authentication successful, obtain the secret key for the user
                    byte[] secretKey = Server.getUserSecretKeys().get(username);

                    // Send encrypted secret key and MAC to client
                    byte[] encryptedSecretKey = encryptSecretKey(secretKey, password);
                    byte[] mac = MACUtils.createMAC(encryptedSecretKey, password);

                    //dataOutputStream.write(encryptedSecretKey);
                    //dataOutputStream.write(mac);

                    out.println("Authentication successful. Proceeding with connection...");
            
                } else {
                    out.println("Invalid username or password.");
                    clientSocket.close();
                    return;
                }
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
                    try {
                        fileHandler.receiveFile(dataInputStream, true);
                    } catch (Exception e) {
                        System.out.println(e);
                    }
                    out.println(fileName + " has been received by server");

                    //send to database
                    dbhandler.sendFile("server_data/" + fileName, fileName);
                    // DatabHandler dbhandler = new DatabHandler();
                    // dbHandler.uploadFile("server_data/" + fileName, fileName);
                }
                else if (inputLine.startsWith("download ")) {
                    String fileName = inputLine.substring(9);
                    FileHandler fileHandler = new FileHandler("server_data/" + fileName);
                    try {
                        fileHandler.sendFile(dataOutputStream, true);
                    } catch (Exception e) {
                        System.out.println(e);
                    }
                    out.println("File Downloaded");
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
                else if (inputLine.equals("pwd")) {
                    FileHandler fileHandler = new FileHandler("server_data/");
                    String output = fileHandler.pwd();
                    out.println(output);
                }
                // else if (inputLine.startsWith("list")) {
                //     String folder = inputLine.substring(4).strip();
                //     if (folder.length() == 0) {
                //         folder = "server_data/";
                //     }
                //     FileHandler fileHandler = new FileHandler(folder);
                //     String output = fileHandler.listFiles();
                //     out.println(output);
                // }
                else {
                    out.println("No command like that available");
                }
            }
            clientSocket.close();
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

    private boolean authenticateUser(String username, byte[] providedPassword) {
        // Validate username and password using server's logic
        // return Server.verifyPassword(password, Server.getUserPasswords().get(username));

        // Get the stored password hash for the given username
        byte[] storedPasswordHash = Server.getUserPasswords().get(username);

        if (storedPasswordHash == null) {
            System.out.println("User not found for username: " + username);
            return false; // User not found
        }

        // Hash the provided password
        byte[] providedPasswordHash = Server.hashPassword(new String(providedPassword));

        // // Compare the hashed passwords
        // return Arrays.equals(providedPasswordHash, storedPasswordHash);
        // Compare the hashed passwords
        boolean isAuthenticated = Arrays.equals(providedPasswordHash, storedPasswordHash);
        System.out.println("providedPasswordHash: " + providedPasswordHash);
        System.out.println("storedPasswordHash: " + storedPasswordHash);

        if (!isAuthenticated) {
            System.out.println("Invalid password for username: " + username);
        }

        return isAuthenticated;
    }

    private byte[] encryptSecretKey(byte[] secretKey, byte[] password) {
        // Implement secret key encryption here
        // For demonstration, just return the secret key
        return secretKey;
    }

    // public void createAccount(String username, byte[] password) {
    //     // Hash the password
    //     byte[] hashedPassword = Server.hashPassword(new String(password));
    
    //     // Store the hashed password in the server's userPasswords map
    //     Server.getUserPasswords().put(username, hashedPassword);
    // }

    private static void createAccount(String username, byte[] password) {
        // Hash the password
        byte[] hashedPassword = Server.hashPassword(new String(password));
    
        // Store the hashed password in the server's userPasswords map
        Server.getUserPasswords().put(username, hashedPassword);
    
        // Generate a secret key for the new account
        byte[] secretKey = generateSecretKey();
    
        // Write the username and secret key to secret_keys.txt file
        writeToSecretKeysFile(username, secretKey);
    }
    
    private static byte[] generateSecretKey() {
        // Generate a new secret key
        // For demonstration, I'll generate a random 16-byte key
        SecureRandom random = new SecureRandom();
        byte[] secretKey = new byte[16];
        random.nextBytes(secretKey);
        return secretKey;
    }
    
    // private static void writeToSecretKeysFile(String username, byte[] secretKey) {
    //     try (FileWriter writer = new FileWriter("secret_keys.txt", true)) {
    //         writer.write(username + ":" + Base64.getEncoder().encodeToString(secretKey) + "\n");
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    // }
    
    private static void writeToSecretKeysFile(String username, byte[] secretKey) {
        // TODO: fix this so that it is only on the server and not my laptop
        File file = new File("/Users/rachelhoman/Documents/CSCI 181 S PO/LodeLM-M3/LodeLM/LodeLMmvn/src/main/java/activities/secret_keys.txt");
        try (FileReader fr = new FileReader(file);
             BufferedReader br = new BufferedReader(fr)) {
            String line;
            StringBuilder fileContent = new StringBuilder();
            boolean found = false;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length >= 2 && parts[0].equals(username)) {
                    // Update the secret key for the existing user
                    // fileContent.append(username).append(":").append(Base64.getEncoder().encodeToString(secretKey)).append("\n");
                    // found = true;
                    System.out.print("User already exists");
                    break;
                } else {
                    // Keep the line unchanged
                    fileContent.append(line).append("\n");
                }
            }
            if (!found) {
                // Append a new entry for the user if not found
                fileContent.append(username).append(":").append(Base64.getEncoder().encodeToString(secretKey)).append("\n");
            }
    
            // Write the updated file content back to the file
            try (FileWriter fw = new FileWriter(file)) {
                fw.write(fileContent.toString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}