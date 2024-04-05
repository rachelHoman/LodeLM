package activities;

import java.io.*;
import java.net.*;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.nio.charset.StandardCharsets;

import java.util.Arrays;
import utils.*;
import javax.crypto.SecretKey;

public class ClientHandler implements Runnable {
    private int AES_KEY_LENGTH = 32;
    private int MAC_KEY_LENGTH = 32; // 256 bits to 32 bytes
    private int BUFFER_SIZE = 4096;

    private Socket clientSocket;

    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    DatabHandler dbhandler = new DatabHandler();

    public void run() {
        try {

            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            FileEncryption fe = new FileEncryption();

            // Receive AES Key
            byte[] aesKey = new byte[AES_KEY_LENGTH];
            dataInputStream.read(aesKey, 0, AES_KEY_LENGTH);
            // aesKey = decryptRSA(aesKey, rsaKey);
            SecretKey aesSecretKey = new SecretKeySpec(aesKey, 0, AES_KEY_LENGTH, "AES");
            System.out.println("AES Key Received");

            // Receive MAC Key
            byte[] macKey = new byte[MAC_KEY_LENGTH];
            dataInputStream.read(macKey, 0, MAC_KEY_LENGTH);
            // macKey = decryptRSA(macKey, rsaKey);
            System.out.println("MAC Key Received");

            // Receive login or create account signal from client
            byte[] actionByte = EncryptedCom.receiveMessage(aesSecretKey, fe, dataInputStream);
            String action = new String(actionByte, StandardCharsets.UTF_8);

            if (action.equals("Create Account") || action.equals("3")) {
                // Receive username from client
                byte[] usernameByte = EncryptedCom.receiveMessage(aesSecretKey, fe, dataInputStream);
                String username = new String(usernameByte, StandardCharsets.UTF_8);

                // Receive encrypted password from client
                byte[] passwordByte = EncryptedCom.receiveMessage(aesSecretKey, fe, dataInputStream);
                String passwordString = new String(passwordByte, StandardCharsets.UTF_8);
                System.out.println(passwordString);

                String sub = Base64.getEncoder().encodeToString(passwordString.getBytes());

                // Ensure proper padding by adding '=' characters if necessary
                int padding = sub.length() % 4;
                if (padding > 0) {
                    sub += "====".substring(padding);
                }

                byte[] password = Base64.getDecoder().decode(sub);

                createAccount(username, password);
                String accountCreation = "Account creation successful. Proceeding with connection...";
                try {
                    EncryptedCom.sendMessage(accountCreation.getBytes(), aesSecretKey, fe, dataOutputStream);
                } catch (Exception e) {
                    System.out.println(e);
                }
            }
            else {
                // Receive username from client
                byte[] usernameByte = EncryptedCom.receiveMessage(aesSecretKey, fe, dataInputStream);
                String username = new String(usernameByte, StandardCharsets.UTF_8);

                // Receive encrypted password from client
                byte[] passwordByte = EncryptedCom.receiveMessage(aesSecretKey, fe, dataInputStream);
                String passwordString = new String(passwordByte, StandardCharsets.UTF_8);

                String sub = Base64.getEncoder().encodeToString(passwordString.getBytes());

                // Ensure proper padding by adding '=' characters if necessary
                int padding = sub.length() % 4;
                if (padding > 0) {
                    sub += "====".substring(padding);
                }

                byte[] password = Base64.getDecoder().decode(sub);

                // Validate username and password
                if (authenticateUser(username, password)) {
                    // If authentication successful, obtain the secret key for the user
                    byte[] secretKey = Server.getUserSecretKeys().get(username);

                    try {
                        String authenticationSuccess = "Authentication successful. Proceeding with connection...";
                        EncryptedCom.sendMessage(authenticationSuccess.getBytes(), aesSecretKey, fe, dataOutputStream);
                    } catch(Exception e) {
                        System.out.println(e);
                    } 
                    
                } else {
                    try {
                        String authenticationFailure = "Invalid username or password.";
                        EncryptedCom.sendMessage(authenticationFailure.getBytes(), aesSecretKey, fe, dataOutputStream);
                    } catch(Exception e) {
                        System.out.println(e);
                    } 
                    clientSocket.close();
                    return;
                }
            }
            // Handle client requests
            // TODO: give the users a list of things they can do on the server to prompt them
            try {
                String output;
                String inputLine;
                while ((inputLine = new String(EncryptedCom.receiveMessage(aesSecretKey, fe, dataInputStream), StandardCharsets.UTF_8)) != null) {

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
                            fileHandler.receiveFile(dataInputStream, aesSecretKey, true);
                        } catch (Exception e) {
                            System.out.println(e);
                        }
                        output = fileName + " has been received by server";
                        EncryptedCom.sendMessage(output.getBytes(), aesSecretKey, fe, dataOutputStream);

                        //send to database
                        dbhandler.sendFile("server_data/" + fileName, fileName);
                        // DatabHandler dbhandler = new DatabHandler();
                        // dbHandler.uploadFile("server_data/" + fileName, fileName);
                    }
                    else if (inputLine.startsWith("download ")) {
                        String fileName = inputLine.substring(9);
                        FileHandler fileHandler = new FileHandler("server_data/" + fileName);
                        try {
                            fileHandler.sendFile(dataOutputStream, aesSecretKey, true);
                        } catch (Exception e) {
                            System.out.println(e);
                        }
                        output = "File Downloaded";
                        EncryptedCom.sendMessage(output.getBytes(), aesSecretKey, fe, dataOutputStream);
                    }
                    else if (inputLine.startsWith("delete ")) {
                        String fileName = inputLine.substring(7);
                        FileHandler fileHandler = new FileHandler("server_data/" + fileName);
                        boolean deleted = fileHandler.deleteFile();
                        if (deleted) {
                            output = fileName + " has been deleted.";
                        } else {
                            output = fileName + " has not been deleted...either does not exist or something else went wrong.";
                        }
                        EncryptedCom.sendMessage(output.getBytes(), aesSecretKey, fe, dataOutputStream);
                    }
                    else if (inputLine.equals("pwd")) {
                        FileHandler fileHandler = new FileHandler("server_data/");
                        output = fileHandler.pwd();
                        EncryptedCom.sendMessage(output.getBytes(), aesSecretKey, fe, dataOutputStream);
                    }
                    else if (inputLine.startsWith("list")) {
                        String folder = inputLine.substring(4).trim();
                        if (folder.length() == 0) {
                            folder = "server_data/";
                        }
                        FileHandler fileHandler = new FileHandler(folder);
                        output = fileHandler.listFiles();
                        EncryptedCom.sendMessage(output.getBytes(), aesSecretKey, fe, dataOutputStream);
                    }
                    else if (inputLine.equals("exit")) {
                        break;
                    }
                    else {
                        output = "No command like that available";
                        EncryptedCom.sendMessage(output.getBytes(), aesSecretKey, fe, dataOutputStream);
                    }
                }
            } catch(Exception e) {
                System.out.println(e);
            } 
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } 
        finally {
            try {
                // Close connections
                dataInputStream.close();
                dataOutputStream.close();
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean authenticateUser(String username, byte[] providedPassword) {

        // Get the stored password hash for the given username
        byte[] storedPasswordHash = (Server.getUserPasswords().get(username)[1]);
        byte[] storedSalt = (Server.getUserPasswords().get(username)[0]);

        if (storedPasswordHash == null || storedSalt == null) {
            return false; 
            // User not found
        }

        // Hash the provided password
        byte[] providedPasswordHash = Server.hashPasswordSalt(new String(providedPassword), storedSalt);

        String encodedSalt = Base64.getEncoder().encodeToString(storedSalt);
        String encodedHashedPasswordP = Base64.getEncoder().encodeToString(providedPasswordHash);
        String encodedHashedPasswordS = Base64.getEncoder().encodeToString(storedPasswordHash);
        // Compare the hashed passwords
        System.out.println("provided: " + encodedHashedPasswordP);
        System.out.println("stored: " + encodedHashedPasswordS);
        System.out.println("salt: " + encodedSalt);
        // System.out.println("salt: " + storedSalt.toString());
        return Arrays.equals(providedPasswordHash, storedPasswordHash);
    }

    private static void createAccount(String username, byte[] password) {

        byte[] salt = generateSalt();
        // CHANGES
        // Server.getUserPasswords().put(username, hashedPassword);

        // Hash the password with Salt
        byte[] hashedPassword = Server.hashPasswordSalt(new String(password), salt);
        // create H(s,p)
        Server.getUserPasswords().put(username, new byte[][]{username.getBytes(), salt, hashedPassword});
    
        // Generate a secret key for the new account
        byte[] secretKey = generateSecretKey();
        // Write the username, secret key, salt, and hashed pwd
        writeToSecretKeysFile(username, secretKey);
        writeToUserFile(username, salt, password);
    }
    
    private static byte[] generateSecretKey() {
        // Generate a new secret key
        // For demonstration, I'll generate a random 16-byte key
        SecureRandom random = new SecureRandom();
        byte[] secretKey = new byte[16];
        random.nextBytes(secretKey);
        return secretKey;
    }

    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32];
        random.nextBytes(salt);
        return salt;
    }

    private static void writeToSecretKeysFile(String username, byte[] secretKey) {
        // TODO: fix this so that it is only on the server and not my laptop
        File file = new File("src/main/java/activities/secret_keys.txt");
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

    private static void writeToUserFile(String username, byte[] salt, byte[] hashedPassword) {
        File file = new File("src/main/java/activities/users.txt");
        try (FileWriter fw = new FileWriter(file, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            // Encode salt and hashed password to Base64 for storage
            String encodedSalt = Base64.getEncoder().encodeToString(salt);
            String encodedHashedPassword = Base64.getEncoder().encodeToString(hashedPassword);
            // Write username, salt, and hashed password to the file
            if (file.length() != 0) { // Check if the file is not empty
                bw.newLine(); // Add a new line if the file is not empty
            }
            // bw.write(username + " " + salt + " " + hashedPassword);
            bw.write(username + " " + encodedSalt + " " + encodedHashedPassword);
            // bw.newLine(); // Add a new line for the next entry
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}