// // import java.io.*;
// // import java.net.*;
// // import java.util.Base64;
// // import java.util.HashMap;
// // import java.util.Map;

// // public class ClientHandler implements Runnable {
// //     private Socket clientSocket;
// //     private PrintWriter out;
// //     private BufferedReader in;
// //     private String username;

// //     public ClientHandler(Socket socket) {
// //         this.clientSocket = socket;
// //     }

// //     public void run() {
// //         try {
// //             out = new PrintWriter(clientSocket.getOutputStream(), true);
// //             in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

// //             // Receive username and password from client
// //             username = in.readLine();
// //             String password = in.readLine();

// //             // Validate username and password
// //             if (authenticateUser(username, password)) {
// //                 out.println("Login successful. Welcome, " + username + "!");

// //                 // Handle client requests
// //                 String inputLine;
// //                 while ((inputLine = in.readLine()) != null) {
// //                     System.out.println("Received from client: " + inputLine);
// //                     // Handle client requests as before
// //                 }
// //             } else {
// //                 out.println("Invalid username or password.");
// //             }
// //         } catch (IOException e) {
// //             e.printStackTrace();
// //         } finally {
// //             try {
// //                 // Close connections
// //                 in.close();
// //                 out.close();
// //                 clientSocket.close();
// //             } catch (IOException e) {
// //                 e.printStackTrace();
// //             }
// //         }
// //     }

// //     private boolean authenticateUser(String username, String password) {
// //         String storedPassword = Server.getUserPasswords().get(username);
// //         if (storedPassword != null) {
// //             // Split the stored password string into salt and hash
// //             String[] parts = storedPassword.split(":");
// //             byte[] salt = Base64.getDecoder().decode(parts[0]);

// //             // Hash the provided password with the stored salt
// //             String hashedPassword = Server.hashPassword(password, salt);

// //             // Compare the hashed passwords
// //             return hashedPassword.equals(storedPassword);
// //         }
// //         return false;
// //     }
// // }

// import java.io.*;
// import java.net.*;
// import java.util.Arrays;
// import java.util.Base64;

// public class ClientHandler implements Runnable {
//     private Socket clientSocket;
//     private PrintWriter out;
//     private BufferedReader in;

//     public ClientHandler(Socket socket) {
//         this.clientSocket = socket;
//     }

//     public void run() {
//         try {
//             out = new PrintWriter(clientSocket.getOutputStream(), true);
//             in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

//             // Receive username and password from client
//             String username = in.readLine();
//             String password = in.readLine();

//             // Validate username and password
//             if (authenticateUser(username, password)) {
//                 out.println("Login successful. Welcome, " + username + "!");
//             } else {
//                 out.println("Invalid username or password.");
//             }
//         } catch (IOException e) {
//             e.printStackTrace();
//         } finally {
//             try {
//                 // Close connections
//                 in.close();
//                 out.close();
//                 clientSocket.close();
//             } catch (IOException e) {
//                 e.printStackTrace();
//             }
//         }
//     }

//     private boolean authenticateUser(String username, String password) {
//         // Validate username and password (you may use your authentication logic here)
//         // For demo purposes, let's just check if the username is "alice" and password is "password123"
//         if (username.equals("alice") && Server.verifyPassword(password, Server.getUserPasswords().get(username))) {
//             byte[] encryptedSecretKey = Server.getUserSecretKeys().get(username);
//             System.out.println("encryptedSecretKey: " + encryptedSecretKey);
//             byte[] decryptedSecretKey = Server.decryptSecretKey(encryptedSecretKey, password);
//             System.out.println("decryptedSecretKey: " + decryptedSecretKey);
//             byte[] storedSecretKey = Server.getUserSecretKeys().get(username);
//             System.out.println("storedSecretKey: " + storedSecretKey);
//             return Arrays.equals(decryptedSecretKey, storedSecretKey);
//         }
//         return false;
//     }
// }


import java.io.*;
import java.net.*;
import java.util.Base64;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void run() {
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // Receive username from client
            String username = in.readLine();
            // Receive encrypted password from client
            String encryptedPasswordBase64 = in.readLine();
            byte[] encryptedPassword = Base64.getDecoder().decode(encryptedPasswordBase64);
            // Decrypt the password
            String password = decryptPassword(encryptedPassword);
            // Validate username and password
            if (authenticateUser(username, password)) {
                out.println("Login successful. Welcome, " + username + "!");
            } else {
                out.println("Invalid username or password.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                // Close connections
                in.close();
                out.close();
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean authenticateUser(String username, String password) {
        // Validate username and password (you may use your authentication logic here)
        // For demo purposes, let's just check if the username is "alice" and password is "password123"
        return username.equals("alice") && password.equals("password123");
    }

    private String decryptPassword(byte[] encryptedPassword) {
        // Implement password decryption here
        return new String(encryptedPassword); // For demonstration, return decrypted password as string
    }
}

