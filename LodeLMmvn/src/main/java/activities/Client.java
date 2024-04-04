package activities;

import java.io.*;
import java.net.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import utils.FileHandler;
import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

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

            // Prompt user to choose login method
            System.out.print("Choose an option: 1. Login, 2. Forgot Password, 3. Create Account \n");
            String login = userInput.readLine();
            if (login.equals("1") || login.equalsIgnoreCase("Login")) {
                // Prompt the user for username
                System.out.print("Enter your username: ");
                String username = userInput.readLine();
                out.println(username); // Send username to server

                // Prompt the user for password
                System.out.print("Enter your password: ");
                String password = userInput.readLine();
                // Encrypt the password
                byte[] encryptedPassword = encryptPassword(password);
                out.println(Base64.getEncoder().encodeToString(encryptedPassword)); // Send encrypted password to server
            }
            else if (login.equals("2") || login.equalsIgnoreCase("Forgot Password")) {

                // Prompt the user for username
                System.out.print("Enter your username: ");
                String username = userInput.readLine();
                // Prompt the user for email
                System.out.print("Enter your email: ");
                String email = userInput.readLine();
                // Prompt the user for recovery question
                System.out.print("Recovery question: Who is your favorite teacher? ");
                String answer = userInput.readLine();
                out.println("alice");
                byte[] encryptedPassword = encryptPassword("password123");
                out.println(Base64.getEncoder().encodeToString(encryptedPassword));

                //out.println(username); // Send username to server
                // TODO: check that this is a valid username and email? pairing and give them the option to reset the password
                // if (email & username is valid) {
                //     reset password
                // }
                // else {
                //     System.out.println("Invalid email or username");
                // }
            }
            else if (login.equals("3") || login.equalsIgnoreCase("Create Account")) {
                // Prompt the user for username
                System.out.print("Enter your username: ");
                String username = userInput.readLine();
                out.println(username); // Send username to server

                // Prompt the user for password
                System.out.print("Enter your password: ");
                String password = userInput.readLine();

                // Prompt the user for email
                System.out.print("Enter your email: ");
                String email = userInput.readLine();

                // Prompt the user for recovery question
                System.out.print("Recovery Question: Who is your favorite teacher? ");
                String teacher = userInput.readLine();

                // Encrypt the password
                byte[] encryptedPassword = encryptPassword(password);
                createAccount(username, encryptedPassword);
                out.println(Base64.getEncoder().encodeToString(encryptedPassword));
            }
            else {
                System.out.println("Not a valid login method");
                // Close connections
                out.println("Client disconnected");
                userInput.close();
                in.close();
                out.close();
                socket.close();
            }

            // Receive and print the greeting message from the server
            String greeting = in.readLine();
            System.out.println(greeting);

            String userMessage;
            while ((userMessage = userInput.readLine()) != null) {

                out.println(userMessage);

                if (userMessage.startsWith("send ")) {
                    String fileName = userMessage.substring(5);
                    FileHandler fileHandler = new FileHandler("client_data/" + fileName);
                    try {
                        fileHandler.sendFile(dataOutputStream, false);
                    } catch (Exception e) {
                        System.out.println(e);
                    }
                }

                else if (userMessage.startsWith("download ")) {
                    String fileName = userMessage.substring(9);
                    FileHandler fileHandler = new FileHandler("client_data/" + fileName);
                    try {
                        fileHandler.receiveFile(dataInputStream, false);
                    } catch (Exception e) {
                        System.out.println(e);
                    }
                }

                // Exit loop if user types 'exit'
                else if (userMessage.equalsIgnoreCase("exit")) {
                    break;
                }

                // Print server responses
                String response;
                while ((response = in.readLine()) != null) { // TODO: this shouldn't go line by line bc if a response has multiple lines then it has to be prompted multiple times to get the full response
                    System.out.println(response);

                    // Break out of inner loop to return to waiting for user input
                    break;
                }

            }

            // Close connections
            out.println("Client disconnected");
            userInput.close();
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private static byte[] encryptPassword(String password) {
        // Implement password encryption here
        return password.getBytes(); // For demonstration, return password as bytes
    }

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
                    fileContent.append(username).append(":").append(Base64.getEncoder().encodeToString(secretKey)).append("\n");
                    found = true;
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