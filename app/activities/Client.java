package app.activities;
import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.util.Base64;
import app.utils.FileHandler;
import app.utils.MACUtils;

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
            out.println(username); // Send username to server

            // Prompt the user for password
            System.out.print("Enter your password: ");
            String password = userInput.readLine();
            // Hash the password
            byte[] hashedPassword = hashPassword(password);
            // Encrypt the hashed password
            byte[] encryptedPassword = encryptPassword(hashedPassword);
            //System.out.println("Encrypted password: " + Base64.getEncoder().encodeToString(encryptedPassword));
            out.println(Base64.getEncoder().encodeToString(encryptedPassword)); // Send encrypted password to server

            // Send username and hashed password to the server
            out.println(username);
            //out.println(Base64.getEncoder().encodeToString(hashedPassword));

            // Receive response from the server
            String response = in.readLine();
            System.out.println("response: " + response);

            // Check if authentication was successful
            if (response.equals("Authentication successful")) {
                System.out.println("Authentication successful. Proceeding with connection...");
                // Receive encrypted secret key and MAC from server
                byte[] encryptedSecretKey = new byte[128]; 
                byte[] mac = new byte[32]; 

                dataInputStream.readFully(encryptedSecretKey);
                dataInputStream.readFully(mac);

                // Verify MAC to ensure integrity of received data
                if (MACUtils.verifyMAC(encryptedSecretKey, mac, hashedPassword)) {
                    out.println("Secret key verified. Proceeding with connection...");
                    // Now the client can proceed with further actions
                } else {
                    out.println("Secret key verification failed. Closing connection.");
                    // Handle failed verification (e.g., close connection)
                    socket.close();
                }
            } else {
                // Authentication failed, handle this case as needed (e.g., terminate connection)
                out.println("Authentication failed. Closing connection.");
                socket.close();
            }

            // Close connections
            userInput.close();
            in.close();
            out.close();
            dataInputStream.close();
            dataOutputStream.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static byte[] hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] encryptPassword(byte[] password) {
        // Implement password encryption here
        // For demonstration, return password as bytes
        // TODO: make sure that this is secure
        return password; 
    }
}
