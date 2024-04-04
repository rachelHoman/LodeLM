package activities;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.net.*;
import java.util.Base64;
import utils.FileHandler;
import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import utils.*;
import javax.crypto.SecretKey;

public class Client {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int SERVER_PORT = 12345;
    private int BUFFER_SIZE = 4096;

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        try {
            Socket socket = new Socket(SERVER_IP, SERVER_PORT);
            System.out.println("Connected to Server");

            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream())); //server input stream
            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in)); //user input stream

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            FileEncryption fe = new FileEncryption();
            SecretKey aesKey;
            SecretKey macKey;

            // AES KEY Communication
            aesKey = fe.getAESKey();
            byte[] keyData =  aesKey.getEncoded();
            //TODO: Encrypt keydata
            dataOutputStream.write(keyData);
            dataOutputStream.flush();
            System.out.println("Secret Key Shared");

            macKey = fe.getHmacKey();
            byte[] macKeyData =  macKey.getEncoded();
            //TODO: Encrypt keydata
            dataOutputStream.write(macKeyData);
            dataOutputStream.flush();
            System.out.println("MAC Key Shared");


            // Prompt the user for username
            System.out.print("Enter your username: ");
            String username = userInput.readLine();
            // out.println(username);
            EncryptedCom.sendMessage(username, aesKey, fe, dataOutputStream); // Send username to server

            // Prompt the user for password
            System.out.print("Enter your password: ");
            String password = userInput.readLine();
            // Encrypt the password
            System.out.println(Base64.getEncoder().encodeToString(password.getBytes()));
            out.println(Base64.getEncoder().encodeToString(password.getBytes())); // Send encrypted password to server

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
}