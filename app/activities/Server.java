package app.activities;
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
    private static final int PORT = 12345;
    public static final String PROJECTS_DIRECTORY = "projects/";
    private static Map<String, byte[]> userSecretKeys = new HashMap<>();
    private static Map<String, byte[]> userPasswords = new HashMap<>();

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

    public static Map<String, byte[]> getUserPasswords() {
        return userPasswords;
    }

    private static void loadUserPasswords() {
        // Load hashed passwords from a file or database
        // For demo purposes, let's initialize with some sample passwords
        // In practice, you would securely store hashed passwords
        // Using a secure hashing algorithm like bcrypt or PBKDF2
        userPasswords.put("alice", hashPassword("password123"));
        userPasswords.put("bob", hashPassword("secret456"));
    }

    private static void loadUserSecretKeysFromFile() {
        // Load encrypted secret keys from a file
        try (BufferedReader reader = new BufferedReader(new FileReader("app/activities/secret_keys.txt"))) {
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

    public static byte[] hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
    }
}

    public static boolean verifyPassword(String providedPassword, byte[] storedPasswordHash) {
        byte[] providedPasswordHash = hashPassword(providedPassword);
        return Arrays.equals(providedPasswordHash, storedPasswordHash);
    }

    // public static byte[] encryptSecretKey(byte[] secretKey, byte[] passwordHash) {
    //     try {
    //         // Ensure the password hash is of appropriate length for AES
    //         byte[] trimmedPasswordHash = Arrays.copyOf(passwordHash, 16); // 16 bytes for AES-128

    //         // Derive a secret key from the trimmed password hash
    //         SecretKeySpec secretKeySpec = new SecretKeySpec(trimmedPasswordHash, "AES");

    //         // Encrypt the secret key using AES
    //         Cipher cipher = Cipher.getInstance("AES");
    //         cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
    //         return cipher.doFinal(secretKey);
    //     } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }

    // public static byte[] decryptSecretKey(byte[] encryptedSecretKey, byte[] passwordHash) {
    //     try {
    //         // Ensure the password hash is of appropriate length for AES
    //         byte[] trimmedPasswordHash = Arrays.copyOf(passwordHash, 16); // 16 bytes for AES-128

    //         // Derive a secret key from the trimmed password hash
    //         SecretKeySpec secretKeySpec = new SecretKeySpec(trimmedPasswordHash, "AES");

    //         // Decrypt the secret key using AES
    //         Cipher cipher = Cipher.getInstance("AES");
    //         cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
    //         return cipher.doFinal(encryptedSecretKey);
    //     } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }

    // public static byte[] encryptSecretKey(byte[] secretKey, byte[] password) {
    //     try {
    //         SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    //         KeySpec spec = new PBEKeySpec(new String(password, StandardCharsets.UTF_8).toCharArray(), new byte[16], 65536, 256);
    //         SecretKey tmp = factory.generateSecret(spec);
    //         SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
    
    //         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    //         cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
    //         return cipher.doFinal(secretKey);
    //     } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
    //             | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }

    public static byte[] encryptSecretKey(byte[] secretKey, byte[] password) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(new String(password, StandardCharsets.UTF_8).toCharArray(), new byte[16], 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
    
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Generate a random IV
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[cipher.getBlockSize()];
            random.nextBytes(ivBytes);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            
            // Prepend IV to the encrypted data
            byte[] encryptedDataWithIV = cipher.doFinal(secretKey);
            byte[] encryptedData = new byte[ivBytes.length + encryptedDataWithIV.length];
            System.arraycopy(ivBytes, 0, encryptedData, 0, ivBytes.length);
            System.arraycopy(encryptedDataWithIV, 0, encryptedData, ivBytes.length, encryptedDataWithIV.length);
    
            return encryptedData;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
    

    // public static byte[] decryptSecretKey(byte[] encryptedSecretKey, byte[] password) {
    //     try {
    //         // Derive a secret key from the password
    //         SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    //         KeySpec spec = new PBEKeySpec(new String(password).toCharArray(), new byte[16], 65536, 256);
    //         SecretKey tmp = factory.generateSecret(spec);
    //         SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
    
    //         // Initialize the cipher with the derived key and IV
    //         Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    //         IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[cipher.getBlockSize()]);
    //         cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
    
    //         // Decrypt the secret key using AES
    //         byte[] decryptedSecretKey = cipher.doFinal(encryptedSecretKey);
    //         return decryptedSecretKey;
    //     } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
    //             | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }
    
    public static byte[] decryptSecretKey(byte[] encryptedSecretKey, byte[] password) {
        try {
            // Derive a secret key from the password
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(new String(password).toCharArray(), new byte[16], 65536, 256);
            SecretKey tmp = factory.generateSecret(spec);
            SecretKey secretKeySpec = new SecretKeySpec(tmp.getEncoded(), "AES");
    
            // Initialize the cipher with the derived key and IV
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Extract IV from the encrypted data
            byte[] ivBytes = Arrays.copyOfRange(encryptedSecretKey, 0, cipher.getBlockSize());
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            
            // Decrypt the data using AES
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedSecretKey = cipher.doFinal(encryptedSecretKey, cipher.getBlockSize(), encryptedSecretKey.length - cipher.getBlockSize());
    
            return decryptedSecretKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
                | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    

    public static byte[] encryptPassword(byte[] password) {
        try {
            // Generate a secure random key for AES encryption
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // Using AES-128
            SecretKey secretKey = keyGen.generateKey();

            // Initialize the cipher with the generated key
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            System.out.println("ecryptPassword password: " + password.toString());
            System.out.println("cipher.doFinal(password): " + cipher.doFinal(password));

            // Encrypt the password
            return cipher.doFinal(password);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] decryptPassword(byte[] encryptedPassword) {
        try {
            // Retrieve the secret key used for encryption
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // Using AES-128
            SecretKey secretKey = keyGen.generateKey();

            // Initialize the cipher with the generated key
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            System.out.println("decryptedPassword: " + encryptedPassword.toString());
            System.out.println("cipher.doFinal(encryptedPassword): " + cipher.doFinal(encryptedPassword));

            // Decrypt the password
            return cipher.doFinal(encryptedPassword);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    // private static byte[] generateRandomBytes(int length) {
    //     byte[] bytes = new byte[length];
    //     new SecureRandom().nextBytes(bytes);
    //     return bytes;
    // }
}

