package activities;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.security.spec.KeySpec;

public class Server {
    // private static final int PORT = 12345;
    private static final int PORT = 53333;
    public static final String PROJECTS_DIRECTORY = "projects/";
    private static Map<String, byte[]> userSecretKeys = new HashMap<>();
    // private static Map<String, byte[][]> userPasswords = new HashMap<>();
    private static Map<String, Map<String, byte[]>> userPasswords = new HashMap<>();
    // private static Map<String, Map<String, String>> userPasswords = new HashMap<>();

    static {
        // Load user passwords from a file or database
        loadUserPasswords();
        // Load user secret keys from a file
        loadUserSecretKeysFromFile();
    }

    public static void main(String[] args) {

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server started. Waiting for clients...");

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);

                // Handle client in a separate thread
                ClientHandler clientHandler = new ClientHandler(clientSocket);
                new Thread(clientHandler).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static Map<String, byte[]> getUserSecretKeys() {
        return userSecretKeys;
    }

    // public static Map<String, byte[][]> getUserPasswords() {
    public static Map<String, Map<String, byte[]>> getUserPasswords() {
    // public static Map<String, Map<String, String>> getUserPasswords() {
        return userPasswords;
    }

    private static void loadUserPasswords() {
        // Load hashed passwords from a file or database
        // TODO: with database make this not hard coded
        // userPasswords.put("alice", hashPassword("password123"));
        // userPasswords.put("bob", hashPassword("secret456"));

        try (BufferedReader reader = new BufferedReader(new FileReader("src/main/java/activities/users.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Split the line into tokens
                String[] tokens = line.split(" ");
                if (tokens.length == 3) {
                    String uid = tokens[0];
                    byte[] salt = Base64.getDecoder().decode(tokens[1]);
                    byte[] hashedPassword = Base64.getDecoder().decode(tokens[2]);
    
                    // Create a nested map to store salt and hashed password
                    Map<String, byte[]> userData = new HashMap<>();
                    userData.put("salt", salt);
                    userData.put("passwordHash", hashedPassword);
    
                    // Store the user information in the map
                    userPasswords.put(uid, userData);
                } else {
                    System.out.println("Invalid format for user entry: " + line);
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading user file: " + e.getMessage());
        }

        // try (BufferedReader reader = new BufferedReader(new FileReader("src/main/java/activities/users.txt"))) {
        //     String line;
        //     while ((line = reader.readLine()) != null) {
        //         // Split the line into tokens
        //         String[] tokens = line.split(" ");
        //         if (tokens.length == 3) {
        //             String uid = tokens[0];
        //             byte[] salt = Base64.getDecoder().decode(tokens[1]);
        //             byte[] hashedPassword = Base64.getDecoder().decode(tokens[2]);
        //             // Store the user information in the map
        //             // userPasswords.put(uid, hashedPassword);
        //             userPasswords.put(uid, new byte[][]{uid.getBytes(), salt, hashedPassword});
        //         } else {
        //             System.out.println("Invalid format for user entry: " + line);
        //         }
        //     }
        // } catch (IOException e) {
        //     System.out.println("Error reading user file: " + e.getMessage());
        // }
    }

    private static void loadUserSecretKeysFromFile() {
        // Load encrypted secret keys from a file
        try (BufferedReader reader = new BufferedReader(new FileReader("src/main/java/activities/secret_keys.txt"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                String username = parts[0];
                byte[] encryptedSecretKey = Base64.getDecoder().decode(parts[1]);
                userSecretKeys.put(username, encryptedSecretKey);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // public static String hashPasswordSalt(String password, byte[] salt) {
    //     try {
    //         MessageDigest digest = MessageDigest.getInstance("SHA-256");
    //         digest.reset();
    //         digest.update(salt);
    //         byte[] hashedBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
    //         return Base64.getEncoder().encodeToString(hashedBytes);
    //     } catch (NoSuchAlgorithmException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }
    

    public static byte[] hashPasswordSalt(String password, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(salt);
            byte[] hashedBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return hashedBytes;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    

    public static byte[] hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // public static byte[] hashPassword(String password) {
    //     try {
    //         // Generate a random salt
    //         byte[] salt = generateRandomBytes(16);
            
    //         // Combine salt and password
    //         byte[] saltedPassword = concatenateByteArrays(salt, password.getBytes());
            
    //         // Hash the salted password
    //         MessageDigest digest = MessageDigest.getInstance("SHA-256");
    //         return digest.digest(saltedPassword);
    //     } catch (NoSuchAlgorithmException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }

    private static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static boolean verifyPassword(byte[] providedPasswordHash, byte[] storedPasswordHash) {
        // Compare the provided password hash with the stored password hash
        return Arrays.equals(providedPasswordHash, storedPasswordHash);
    }

    public static byte[] encryptSecretKey(byte[] secretKey, byte[] passwordHash) {
        try {
            // Ensure the password hash is of appropriate length for AES
            byte[] trimmedPasswordHash = Arrays.copyOf(passwordHash, 16); // 16 bytes for AES-128

            // Derive a secret key from the trimmed password hash
            SecretKeySpec secretKeySpec = new SecretKeySpec(trimmedPasswordHash, "AES");

            // Encrypt the secret key using AES
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(secretKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decryptSecretKey(byte[] encryptedSecretKey, byte[] passwordHash) {
        try {
            // Ensure the password hash is of appropriate length for AES
            byte[] trimmedPasswordHash = Arrays.copyOf(passwordHash, 16); // 16 bytes for AES-128

            // Derive a secret key from the trimmed password hash
            SecretKeySpec secretKeySpec = new SecretKeySpec(trimmedPasswordHash, "AES");

            // Decrypt the secret key using AES
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher.doFinal(encryptedSecretKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // public void writeToSecretKeysFile(String username, byte[] secretKey) {
    //     try (FileWriter writer = new FileWriter("LodeLMmvn/src/main/java/activities/secret_keys.txt", true)) {
    //         writer.write(username + ":" + Base64.getEncoder().encodeToString(secretKey) + "\n");
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    // }

    
}