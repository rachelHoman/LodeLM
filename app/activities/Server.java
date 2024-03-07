<<<<<<< HEAD:Server.java
import javax.crypto.*;
import javax.crypto.spec.*;
=======
package app.activities;

>>>>>>> master:app/activities/Server.java
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.security.spec.KeySpec;

public class Server {
    private static final int PORT = 12345;
    public static final String PROJECTS_DIRECTORY = "projects/";
    private static Map<String, byte[]> userSecretKeys = new HashMap<>();
    private static Map<String, String> userPasswords = new HashMap<>();

    static {
        // Load user secret keys and passwords from files (or initialize them)
        loadUserSecretKeys();
        loadUserPasswords();
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

    public static Map<String, String> getUserPasswords() {
        return userPasswords;
    }

    private static void loadUserSecretKeys() {
        // Load user secret keys from a file or database
        // For demo purposes, let's initialize with some sample keys
        // Here, we're just using random bytes as secret keys
        // In practice, you would securely generate and store these keys
        userSecretKeys.put("alice", generateRandomBytes(16));
        userSecretKeys.put("bob", generateRandomBytes(16));
    }

    private static void loadUserPasswords() {
        // Load hashed passwords from a file or database
        // For demo purposes, let's initialize with some sample passwords
        // In practice, you would securely store hashed passwords
        // Using a secure hashing algorithm like bcrypt or PBKDF2
        userPasswords.put("alice", hashPassword("password123", generateRandomBytes(16)));
        userPasswords.put("bob", hashPassword("secret456", generateRandomBytes(16)));
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    public static String hashPassword(String password, byte[] salt) {
        try {
            // Hash the password with PBKDF2 using the provided salt
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
            byte[] hash = skf.generateSecret(spec).getEncoded();

            // Combine the salt and hash into a single string for storage
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] encryptSecretKey(byte[] secretKey, String password) {
        try {
            // Derive a secret key from the password
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), new byte[16], 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");

            // Encrypt the secret key using AES
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher.doFinal(secretKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decryptSecretKey(byte[] encryptedSecretKey, String password) {
        try {
            // Derive a secret key from the password
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), new byte[16], 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
    
            // Initialize the cipher with the derived key and IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[cipher.getBlockSize()]);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
    
            // Decrypt the secret key using AES
            byte[] decryptedSecretKey = cipher.doFinal(encryptedSecretKey);
            return decryptedSecretKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
    

    public static boolean verifyPassword(String providedPassword, String storedPassword) {
        try {
            // Split the stored password string into salt and hash
            String[] parts = storedPassword.split(":");
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] storedHash = Base64.getDecoder().decode(parts[1]);

            // Hash the provided password with the stored salt
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec(providedPassword.toCharArray(), salt, 65536, 128);
            SecretKey key = skf.generateSecret(spec);
            byte[] providedHash = key.getEncoded();

            // Compare the provided hash with the stored hash
            return MessageDigest.isEqual(storedHash, providedHash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return false;
        }
    }
}
