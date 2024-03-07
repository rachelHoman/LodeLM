<<<<<<< HEAD:ClientHandler.java
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
=======
package app.activities;

import java.io.*;
import java.net.*;
import java.util.List;
import java.util.ArrayList;
import app.utils.FileHandler;
>>>>>>> master:app/activities/ClientHandler.java

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
<<<<<<< HEAD:ClientHandler.java
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
=======
            this.username = in.readLine();
            System.out.println("Received username: " + this.username);

            // Initialize project list for the user
            // TODO: connect username to user database object and pull in associated user projects from there, not the server class
            List<String> userProjects = Server.getUserProjects().computeIfAbsent(username, k -> new ArrayList<>());

            // Send greeting message to client
            out.println("Hi " + this.username);

            // Handle client requests
            // TODO: give the users a list of things they can do on the server to prompt them
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received from client: " + inputLine);

                // Handle create project command
                if (inputLine.startsWith("create ")) {
                    String projectName = inputLine.substring(7); // Extract project name
                    if (createProject(projectName, userProjects)) {
                        out.println("Project '" + projectName + "' created successfully.");
                    } else {
                        out.println("Failed to create project '" + projectName + "'.");
                    }
                } 
                // Handle list projects command
                else if (inputLine.equals("list projects")) {
                    out.println("Your projects: " + userProjects.toString());
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
>>>>>>> master:app/activities/ClientHandler.java
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

<<<<<<< HEAD:ClientHandler.java
    private boolean authenticateUser(String username, String password) {
        // Validate username and password (you may use your authentication logic here)
        // For demo purposes, let's just check if the username is "alice" and password is "password123"
        return username.equals("alice") && password.equals("password123");
    }
=======
    private boolean createProject(String projectName, List<String> userProjects) {
        try {
            // TODO: make this a projects object not directory bc we don't want to save this on our local devices
            // Create the "projects" directory if it doesn't exist 
            File projectsDir = new File(Server.PROJECTS_DIRECTORY);
            if (!projectsDir.exists()) {
                projectsDir.mkdirs(); // mkdirs() will create parent directories if necessary
            }
>>>>>>> master:app/activities/ClientHandler.java

    private String decryptPassword(byte[] encryptedPassword) {
        // Implement password decryption here
        return new String(encryptedPassword); // For demonstration, return decrypted password as string
    }
}

