package activities;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.net.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.security.*;
import java.security.cert.CertificateException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import org.apache.commons.lang3.StringUtils;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import utils.*;
import javax.crypto.SecretKey;

public class Client {
    private static final String SERVER_IP = "127.0.0.1";
    // private static final int SERVER_PORT = 17639;
    private static final int SERVER_PORT = 57719;
    private int BUFFER_SIZE = 4096;

    private static final String protocol = "TLSv1.2";
    private static final String[] cipher_suites = new String[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"};

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, KeyStoreException, CertificateException, KeyManagementException {
        SSLSocket socket = null;
        BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in)); //user input stream

        try {
            String truststorePath = "./trust.keystore"; // Contains the self-signed cert or CA
            String truststorePassword = "lodelm"; 

            try {
                // Load Truststore (contains trusted certificates)
                KeyStore trustStore = KeyStore.getInstance("JKS");
                trustStore.load(new FileInputStream(truststorePath), truststorePassword.toCharArray());
            
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(trustStore);
                
                // Create SSLContext
                SSLContext sslContext = SSLContext.getInstance(protocol);
                sslContext.init(null, tmf.getTrustManagers(), null);
                
                SSLSocketFactory factory = sslContext.getSocketFactory();
                socket = (SSLSocket) factory.createSocket(SERVER_IP, SERVER_PORT);
                socket.setEnabledCipherSuites(cipher_suites); 
                socket.startHandshake(); 

                System.out.println("Connected to Server");

                
                DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

                FileEncryption fe = new FileEncryption();
                SecretKey aesKey;
                SecretKey macKey;

                // AES KEY Communication
                aesKey = fe.getAESKey();
                byte[] keyData =  aesKey.getEncoded();
                dataOutputStream.write(keyData);
                dataOutputStream.flush();
                System.out.println("Secret Key Shared");

                String username = "";
                boolean loggedIn = false;
                while (!loggedIn) {
                    // Prompt user to choose login method
                    System.out.print("Choose an option: 1. Login, 2. Forgot Password, 3. Create Account, 4. Exit\n");
                    String login = userInput.readLine();
                    if (login.equals("1") || login.equalsIgnoreCase("Login")) {
                        // sending action to server
                        EncryptedCom.sendMessage(login.getBytes(), aesKey, fe, dataOutputStream);
                        // Prompt the user for username
                        System.out.print("Enter your username: ");
                        username = userInput.readLine();
                        // case for user not existing
                        while (!UserExists(username, "normal")) {
                            System.out.print("Username is incorrect or does not exist. Enter another username: ");
                            username = userInput.readLine();
                        }
                        EncryptedCom.sendMessage(username.getBytes(), aesKey, fe, dataOutputStream); // Send username to server

                        // Prompt the user for password
                        System.out.print("Enter your password: ");
                        String password = userInput.readLine();
                        // Send encrypt password
                        EncryptedCom.sendMessage(password.getBytes(), aesKey, fe, dataOutputStream); // Send password to server
                    }
                    else if (login.equals("2") || login.equalsIgnoreCase("Forgot Password")) {
                        // sending action to server
                        EncryptedCom.sendMessage(login.getBytes(), aesKey, fe, dataOutputStream);

                        username = "";
                        String email = "";
                        // Get valid email entry
                        while (true) {
                            // Prompt the user for username
                            System.out.print("Enter your username: ");
                            username = userInput.readLine();

                            // case for user not existing
                            while (!UserExists(username, "normal")) {
                                System.out.print("Username is incorrect or does not exist. Enter another username: ");
                                username = userInput.readLine();
                            }
                            System.out.print("Enter your email: ");
                            email = userInput.readLine();

                            if (email.isEmpty()) {
                                System.out.println("Email cannot be empty. Please enter valid values.");
                                continue;
                            }

                            // Check if the email is valid
                            if (!SimpleMailSender.isValidEmail(email)) {
                                System.out.println("Invalid email format. Please enter valid values.");
                                continue;
                            }

                            // Check if email and username match
                            if (!UserEmailMatch(username, email, "normal")) {
                                System.out.println("Username or Email are incorrect. Please enter a valid username and email.");
                                continue;
                            }

                            // Password re-set email
                            System.out.println("Sending one-time passcode to your email...");
                            String otpVal = SimpleMailSender.generateOTP();
                            String emailSubject = "Password Reset";
                            String emailBody = "Dear " + username + ",\n\n"
                                            + "Your one-time passcode for password reset is: " + otpVal + "\n"
                                            + "Please use this passcode to reset your password.\n\n"
                                            + "Regards,\n"
                                            + "Your LodeLM Team";
                            SimpleMailSender.sendEmail(email, emailSubject, emailBody);

                            System.out.print("Enter your one-time passcode: ");
                            String answer = userInput.readLine();
                            if (answer.equals(otpVal)) {
                                System.out.print("Enter your new password: ");
                                String password = userInput.readLine();
                                while (!isPasswordStrong(password)) {
                                    String errorMessage = "Password is not strong enough. Please choose a password with at least 8 characters, containing at least one digit, one uppercase letter, one lowercase letter, and one special character. \n";
                                    System.out.print(errorMessage);
                                    System.out.print("Try again please. Enter your password: ");
                                    password = userInput.readLine();
                                }
                                System.out.print("Retype your password: ");
                                String password2 = userInput.readLine();
                                while (!password.equals(password2)){
                                    System.out.println("Passwords do not match"); 
                                    System.out.println("Please try again: "); 
                                    password2 = userInput.readLine();
                                }
                                logAuditAction(username, "Forgot Password", "Password Recovered", "audit_log.txt");
                                EncryptedCom.sendMessage(username.getBytes(), aesKey, fe, dataOutputStream);
                                EncryptedCom.sendMessage(password.getBytes(), aesKey, fe, dataOutputStream);
                                EncryptedCom.sendMessage(email.getBytes(), aesKey, fe, dataOutputStream);
                                break;
                            } else {
                                System.out.println("Incorrect Answer");
                                logAuditAction(username, "Forgot Password", "Failed Password Recovery", "audit_log.txt");

                            }
                        }
                    }
                    else if (login.equals("3") || login.equalsIgnoreCase("Create Account")) {
                        // Send a signal to the server indicating account creation
                        EncryptedCom.sendMessage(login.getBytes(), aesKey, fe, dataOutputStream);
                        // Prompt the user for username
                        System.out.print("Enter your username: ");
                        username = userInput.readLine();

                        while (UserExists(username, "normal")) {
                            System.out.print("Username exists. Enter another username: ");
                            username = userInput.readLine();
                        }
                        if (username.isEmpty() || username.contains(" ")) {
                            System.out.println("Username cannot be empty. Please enter valid values.");
                            continue;
                        }

                        // Prompt the user for password twice
                        System.out.print("Enter your password: ");
                        String password = userInput.readLine();
                        while (!isPasswordStrong(password)) {
                            String errorMessage = "Password is not strong enough. Please choose a password with at least 8 characters, containing at least one digit, one uppercase letter, one lowercase letter, and one special character.";
                            System.out.print(errorMessage);
                            System.out.print("Try again please. Enter your password: ");
                            password = userInput.readLine();
                        }
                        System.out.print("Enter your password again: ");
                        String password2 = userInput.readLine();
                        while (!password.equals(password2)){
                            System.out.print("Passwords do not match.");
                            System.out.print("Please try again:");
                            password2 = userInput.readLine();
                        }

                        String email = "";
                        // Get valid email entry
                        while (true) {
                            System.out.print("Enter your email: ");
                            email = userInput.readLine();

                            if (email.isEmpty()) {
                                System.out.println("Email cannot be empty. Please enter a valid email.");
                                continue;
                            }

                            // Check if the email is valid
                            if (!SimpleMailSender.isValidEmail(email)) {
                                System.out.println("Invalid email format. Please enter a valid email.");
                                continue;
                            }

                            // Verifying email
                            System.out.println("Sending one-time passcode to your email...");
                            String otpVal = SimpleMailSender.generateOTP();
                            String emailSubject = "Email Verification";
                            String emailBody = "Dear " + username + ",\n\n"
                                            + "Your one-time passcode is: " + otpVal + "\n"
                                            + "Please use this passcode to verify your email.\n\n"
                                            + "Regards,\n"
                                            + "Your LodeLM Team";
                            SimpleMailSender.sendEmail(email, emailSubject, emailBody);

                            System.out.print("Enter your one-time passcode: ");
                            String answer = userInput.readLine();
                            if (answer.equals(otpVal)) {
                                System.out.println("Your email has been verified!");
                                break;
                            } else {
                                logAuditAction(username, "Create Account", "Invalid password", "audit_log.txt");
                                System.out.println("Your email was invalid. Please enter a valid email.");
                            }
                        }

                        // Encrypt the password
                        logAuditAction(username, "Create Account", "Account Created", "audit_log.txt");
                        EncryptedCom.sendMessage(username.getBytes(), aesKey, fe, dataOutputStream);
                        EncryptedCom.sendMessage(password.getBytes(), aesKey, fe, dataOutputStream);
                        EncryptedCom.sendMessage(email.getBytes(), aesKey, fe, dataOutputStream);

                    }
                    else if (login.equals("4") || login.equalsIgnoreCase("Exit")) {
                        // Send exit command to the server
                        EncryptedCom.sendMessage("exit".getBytes(), aesKey, fe, dataOutputStream);
                        // Close connections
                        userInput.close();
                        socket.close();
                        dataInputStream.close();
                        dataOutputStream.close();
                        logAuditAction(username, "Client", "Logout", "audit_log.txt");
                        return;
                    }
                    else {
                        System.out.println("Not a valid login method");
                        continue;
                    }

                    // Receive and print the greeting message from the server
                    byte[] greetingByte = EncryptedCom.receiveMessage(aesKey, fe, dataInputStream);
                    String greeting = new String(greetingByte, StandardCharsets.UTF_8);
                    System.out.println(greeting);
                    if (!greeting.equals("Invalid username or password.")) {
                        loggedIn = true;
                        logAuditAction(username, "Normal", "Login", "audit_log.txt");
                        // After successful authentication
                        String loggedInMessage = "logged-in";
                        EncryptedCom.sendMessage(loggedInMessage.getBytes(), aesKey, fe, dataOutputStream);
                    }
                }

                String userMessage;
                while ((userMessage = userInput.readLine()) != null) {

                    EncryptedCom.sendMessage(userMessage.getBytes(), aesKey, fe, dataOutputStream);

                    if (userMessage.startsWith("send ")) {
                        String fileName = userMessage.substring(5);
                        String filePath = "client_data/" + fileName;
                        File fileToSend = new File(filePath);

                        if (fileToSend.exists()) {
                        FileHandler fileHandler = new FileHandler(filePath);
                        try {
                            fileHandler.sendFile(dataOutputStream, aesKey, false, username);
                        } catch (Exception e) {
                            System.out.println(e);
                        }
                        }

                        else {
                            System.out.println("This file does not exist or is a directory");
                            continue;
                        }
                        
                    }

                    else if (userMessage.startsWith("download ")) {
                        String fileName = userMessage.substring(9);
                        File fileToDownload = new File("server_data/" + fileName);

                        if (fileToDownload.exists()) {
                            FileHandler fileHandler = new FileHandler("client_data/" + fileName);
                            try {
                                fileHandler.receiveFile(dataInputStream, aesKey, false, username);
                            } catch (Exception e) {
                                System.out.println(e);
                            }
                        }

                        else {
                            System.out.println(fileName + " does not exist or is a directory");
                            continue;
                        }

                    }

                    // Exit loop if user types 'exit'
                    else if (userMessage.equalsIgnoreCase("exit")) {
                        logAuditAction(username, "User", "Logout", "audit_log.txt");
                        break;
                    }

                    // Print server responses
                    String response;
                    while ((response = new String(EncryptedCom.receiveMessage(aesKey, fe, dataInputStream), StandardCharsets.UTF_8)) != null) { 
                        System.out.println(response);

                        // Break out of inner loop to return to waiting for user input
                        break;
                    }

                }

                // Close connections
                userInput.close();
                socket.close();

            } catch (SocketTimeoutException e) {
                // Handle timeout: log the event
                logAuditAction("Client", "Idle", "Idle for 5 min", "audit_log.txt");
                System.out.println("Connection timed out due to inactivity.");
            } catch (IOException e) {
                // Handle other IO exceptions
                e.printStackTrace();
            } finally {
                // Close resources
                try {
                    if (userInput != null)
                        userInput.close();
                    if (socket != null)
                        socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public static boolean UserExists(String username, String userMode) {
        Map<String, byte[]> userData;
        if (userMode.equals("test")) {
            userData = Server.testGetUserPasswords().get(username);
        }
        else {
            userData = Server.getUserPasswords().get(username);
        }

        if (userData == null) {
            return false;
        }
        else {
            return true;
        }
    }

    public static boolean UserEmailMatch (String username, String providedEmail, String userMode) {
        Map<String, byte[]> userData;
        if (userMode.equals("test")) {
            userData = Server.testGetUserPasswords().get(username);
        }
        else {
            userData = Server.getUserPasswords().get(username);
        }
        
        if (userData == null) {
            return false;
        }
        else {
            // Get the stored salt and password email
            byte[] storedSalt = userData.get("salt");
            byte[] storedEmailHash = userData.get("emailHash");
            if (storedSalt == null || storedEmailHash == null) {
                return false;
            }
            // Hash the provided email
            byte[] providedEmailHash = Server.hashSalt(providedEmail, storedSalt);
            return Arrays.equals(providedEmailHash, storedEmailHash);
        }
    }

    public static boolean isPasswordStrong(String password) {
        if (StringUtils.isBlank(password) || password.length() < 8) {
            return false;
        }
    
        // Count special characters
        int specialCharCount = 0;
        for (char ch : password.toCharArray()) {
            if (!Character.isLetterOrDigit(ch)) {
                specialCharCount++;
            }
        }
    
        // Check if password contains at least one digit, one uppercase, and one lowercase character
        boolean containsDigit = StringUtils.containsAny(password, "1234567890");
        boolean containsUppercase = StringUtils.containsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        boolean containsLowercase = StringUtils.containsAny(password, "abcdefghijklmnopqrstuvwxyz");
    
        return containsDigit && containsUppercase && containsLowercase && specialCharCount >= 1;
    }

    // Method to log audit action
    public static void logAuditAction(String username, String permissionLevel, String action, String filename) {
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        String logEntry = username + "," + permissionLevel + "," + timestamp + "," + action;

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename, true))) {
            writer.write(logEntry);
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Error writing to audit log: " + e.getMessage());
        }
    }

    public static void logoutUser(Socket clientSocket, DataInputStream dataInputStream, DataOutputStream dataOutputStream, BufferedReader userInput){
        try {
            // Close the socket
            clientSocket.close();
            dataInputStream.close();
            dataOutputStream.close();
            userInput.close();
        } catch (IOException e) {
            System.out.println("Error closing socket: " + e.getMessage());
        }
        return;
    }

}