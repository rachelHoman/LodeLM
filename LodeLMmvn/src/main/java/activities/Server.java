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

import utils.FileEncryption;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

public class Server {
    // private static final int PORT = 17639;
    private static final int PORT = 57719;

    private static final String protocol = "TLSv1.2";
    private static final String[] cipher_suites = new String[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"};

    private static final String path_to_keystore = "./server.jks";

    public static final String PROJECTS_DIRECTORY = "projects/";
    private static Map<String, byte[]> userSecretKeys = new HashMap<>();
    private static Map<String, byte[]> testuserSecretKeys = new HashMap<>();
    private static Map<String, Map<String, byte[]>> userPasswords = new HashMap<>();
    private static Map<String, Map<String, byte[]>> testuserPasswords = new HashMap<>();
    private static String userPath = "src/main/java/activities/users.txt";
    private static String testPath = "src/test/java/activities/test_users.txt";
    private static String secretPath = "src/main/java/activities/secret_keys.txt";
    private static String testsecretPath = "src/test/java/activities/test_secret_keys.txt";

    static {
        loadUserPasswords(userPath);
        loadUserPasswords(testPath);
        loadUserSecretKeysFromFile(secretPath);
        loadUserSecretKeysFromFile(testsecretPath);
    }

    public static void main(String[] args) {

        SSLServerSocket serverSocket = null;

        // Create server key to encrypt files if key does not exist
        File serverKeyFile = new File("../file_keys.csv");
        if (!serverKeyFile.exists()) {
            try {
                FileEncryption fe = new FileEncryption();
                SecretKey serverKey = fe.getAESKey();
                fe.saveKey(serverKey, serverKeyFile);
            } catch (Exception e) {
                System.out.println(e);
            }
        }

        try {
            // Keystore Configuration
            String keystorePath = "./server.keystore";
            String keystorePassword = "lodelm";

            // Certificate Trust Configuration (if using a self-signed certificate)
            String truststorePath = "./trust.keystore"; // Contains the self-signed cert or CA
            String truststorePassword = "lodelm";

            try {
                // Load Keystore (contains server's certificate and private key)
                KeyStore keyStore = KeyStore.getInstance("JKS");
                keyStore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());

                // Load Truststore (contains trusted certificates)
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(new FileInputStream(truststorePath), truststorePassword.toCharArray());

                // Initialize KeyManager and TrustManager
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keystorePassword.toCharArray());

                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);

                // Create SSLContext
                SSLContext sslContext = SSLContext.getInstance(protocol);
                sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

                // Create Server Socket Factory
                SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

                // Bind server to specified port and enable protocols and cipher suites.
                serverSocket = (SSLServerSocket) factory.createServerSocket(PORT);
                serverSocket.setEnabledCipherSuites(cipher_suites);

                System.out.println("Server started. Waiting for clients...");

                while (true) {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    System.out.println("Client connected: " + clientSocket);

                    // Handle client in a separate thread
                    ClientHandler clientHandler = new ClientHandler(clientSocket);
                    new Thread(clientHandler).start();
                }
            } catch (Exception e) {
                System.out.println(e);
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }

    public static Map<String, byte[]> getUserSecretKeys() {
        return userSecretKeys;
    }

    public static Map<String, byte[]> testGetUserSecretKeys() {
        return testuserSecretKeys;
    }

    public static Map<String, Map<String, byte[]>> getUserPasswords() {
        return userPasswords;
    }

    public static Map<String, Map<String, byte[]>> testGetUserPasswords() {
        return testuserPasswords;
    }

    private static void loadUserPasswords(String filePath) {

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Split the line into tokens
                String[] tokens = line.split(" ");
                if (tokens.length == 4) {
                    String uid = tokens[0];
                    byte[] salt = Base64.getDecoder().decode(tokens[1]);
                    byte[] hashedPassword = Base64.getDecoder().decode(tokens[2]);
                    byte[] hashedEmail = Base64.getDecoder().decode(tokens[3]);
                    if (filePath.equals(userPath)) {
                        // Create a nested map to store salt and hashed password
                        Map<String, byte[]> userData = new HashMap<>();
                        userData.put("salt", salt);
                        userData.put("passwordHash", hashedPassword);
                        userData.put("emailHash", hashedEmail);
        
                        // Store the user information in the map
                        userPasswords.put(uid, userData);
                    }
                    else if (filePath.equals(testPath)) {
                        // hash password and email for test
                        byte[] hashedPasswordForTest = hashSalt(new String(Base64.getDecoder().decode(tokens[2]), StandardCharsets.UTF_8), salt);
                        byte[] hashedEmailForTest = hashSalt(new String(Base64.getDecoder().decode(tokens[3]), StandardCharsets.UTF_8), salt);
                        // Create a nested map to store salt and hashed password
                        Map<String, byte[]> testuserData = new HashMap<>();
                        testuserData.put("salt", salt);
                        testuserData.put("passwordHash", hashedPasswordForTest);
                        testuserData.put("emailHash", hashedEmailForTest);
        
                        // Store the user information in the map
                        testuserPasswords.put(uid, testuserData);
                    }
                } else {
                    System.out.println("testData: " + testuserPasswords);
                    System.out.println("Invalid format for user entry: " + line);
                }
            }
        } catch (IOException e) {
            System.out.println("Error reading user file: " + e.getMessage());
        }
    }

    private static void loadUserSecretKeysFromFile(String filePath) {
        // Load encrypted secret keys from a file
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(":");
                String username = parts[0];
                byte[] encryptedSecretKey = Base64.getDecoder().decode(parts[1]);
                if (filePath.equals(testsecretPath)) {
                    testuserSecretKeys.put(username, encryptedSecretKey);
                }
                else {
                    userSecretKeys.put(username, encryptedSecretKey);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    

    public static byte[] hashSalt(String password, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(salt);
            byte[] hashedBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            // iterations
            for (int i = 0; i < 20000; i++) {
                digest.reset();
                hashedBytes = digest.digest(hashedBytes);
            }
            return hashedBytes;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
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
}