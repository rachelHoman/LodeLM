package activities;
import org.junit.*;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.*;
import java.net.*;

import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.file.Files;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import activities.Client;
import activities.Server;
import utils.*;
import java.util.Arrays;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.google.firebase.database.DatabaseReference;
import com.opencsv.exceptions.CsvValidationException;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.api.mockito.PowerMockito;


public class ClientServerTest {
    private Server server;
    private Client client;
    int port = 12345;

    FileEncryption fe = new FileEncryption();

    @Test
    public void aesEncryptDecryptTest1() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        SecretKey aesKey = fe.getAESKey();
        String test = "hello";
        byte[] cipherText = this.fe.AESEncrypt(test.getBytes(), aesKey);
        byte[] iv = this.fe.getIV();
        assertTrue(!test.equals(new String(cipherText, StandardCharsets.UTF_8)));
        byte[] decryptedTextByte = this.fe.AESDecrypt(cipherText, aesKey, iv);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(test.equals(decryptedText));
    } 
    @Test
    public void aesEncryptDecryptTest2() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        SecretKey aesKey = fe.getAESKey();
        String test = " ";
        byte[] cipherText = this.fe.AESEncrypt(test.getBytes(), aesKey);
        byte[] iv = this.fe.getIV();
        assertTrue(!test.equals(new String(cipherText, StandardCharsets.UTF_8)));
        byte[] decryptedTextByte = this.fe.AESDecrypt(cipherText, aesKey, iv);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(test.equals(decryptedText));
    } 
    @Test
    public void aesEncryptDecryptTest3() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        SecretKey aesKey = fe.getAESKey();
        String test = "00000000000000000000000000000000000000000000000000000000000000000000000000";
        byte[] cipherText = this.fe.AESEncrypt(test.getBytes(), aesKey);
        byte[] iv = this.fe.getIV();
        assertTrue(!test.equals(new String(cipherText, StandardCharsets.UTF_8)));
        byte[] decryptedTextByte = this.fe.AESDecrypt(cipherText, aesKey, iv);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(test.equals(decryptedText));
    } 

    @Test
    public void fileEncryptDecryptTest() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        String filename = "client_data/file.txt";
        File file = new File(filename);
        byte[] fileContent = Files.readAllBytes(file.toPath());
        String fileContent1 = new String(fileContent, StandardCharsets.UTF_8);

        byte[] cipherText = this.fe.encryptFile(file);
        String cipherText1 = new String(cipherText, StandardCharsets.UTF_8);
        byte[] iv = this.fe.getIV();
        assertTrue(!fileContent1.equals(cipherText1));

        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(iv);
        fileOutputStream.write(cipherText);
        fileOutputStream.close();

        SecretKey aesKey = fe.getSK();
        byte[] decryptedTextByte = this.fe.decryptFile(file, aesKey);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(fileContent1.equals(decryptedText));
    } 

    private static byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }



    // Testing Server.java

    @Test
    public void testLoadUserPasswordsKeys() {
        prepareTestFile();
        Map<String, Map<String, byte[]>> testuserPasswords = Server.testGetUserPasswords();
        assertNotNull(testuserPasswords);
        assertTrue(testuserPasswords.containsKey("testUser1"));
        assertTrue(testuserPasswords.containsKey("testUser2"));
    }

    @Test
    public void testLoadUserPasswordsInnerKeysTrue() {
        prepareTestFile();
        Map<String, Map<String, byte[]>> testuserPasswords = Server.testGetUserPasswords();
        Map<String, byte[]> testuserData1 = testuserPasswords.get("testUser1");
        assertNotNull(testuserData1);
        assertTrue(testuserData1.containsKey("salt"));
        assertTrue(testuserData1.containsKey("passwordHash"));
    }

    @Test
    public void testLoadUserPasswordsValuesTrue() {
        prepareTestFile();
        Map<String, Map<String, byte[]>> testuserPasswords = Server.testGetUserPasswords();
        
        Map<String, byte[]> testuserData1 = testuserPasswords.get("testUser1");
        assertTrue((encodeBase64("salt1")).equals(Base64.getEncoder().encodeToString(testuserData1.get("salt"))));
        assertTrue((encodeBase64("hashedPassword1")).equals(Base64.getEncoder().encodeToString(testuserData1.get("passwordHash"))));

        Map<String, byte[]> testuserData2 = testuserPasswords.get("testUser2");
        assertTrue((encodeBase64("salt2")).equals(Base64.getEncoder().encodeToString(testuserData2.get("salt"))));
        assertTrue((encodeBase64("hashedPassword2")).equals(Base64.getEncoder().encodeToString(testuserData2.get("passwordHash"))));
    }

    @Test
    public void testLoadUserPasswordsValuesFalse() {
        prepareTestFile();
        Map<String, Map<String, byte[]>> testuserPasswords = Server.testGetUserPasswords();
        
        Map<String, byte[]> testuserData1 = testuserPasswords.get("testUser1");
        assertFalse((encodeBase64("salt2")).equals(Base64.getEncoder().encodeToString(testuserData1.get("salt"))));
        assertFalse((encodeBase64("hashedPassword")).equals(Base64.getEncoder().encodeToString(testuserData1.get("passwordHash"))));

        Map<String, byte[]> testuserData2 = testuserPasswords.get("testUser2");
        assertFalse((encodeBase64("salt")).equals(Base64.getEncoder().encodeToString(testuserData2.get("salt"))));
        assertFalse((encodeBase64("hashedPasswod2")).equals(Base64.getEncoder().encodeToString(testuserData2.get("passwordHash"))));
    }

    @Test
    public void testLoadUserPasswordsError() {
        prepareTestFile();
        Map<String, Map<String, byte[]>> testuserPasswords = Server.testGetUserPasswords();
        Map<String, byte[]> testuserData1 = testuserPasswords.get("testUser1");
        assertFalse((encodeBase64("salt2")).equals(Base64.getEncoder().encodeToString(testuserData1.get("salt"))));
        assertFalse((encodeBase64("hashedPassword")).equals(Base64.getEncoder().encodeToString(testuserData1.get("passwordHash"))));
    }

    @Test
    public void testLoadUserSecretKeysFromFile() {
        prepareTestFile();
        Map<String, byte[]> testSecretKeys = Server.testGetUserSecretKeys();
        assertEquals(2, testSecretKeys.size());
        assertTrue(testSecretKeys.containsKey("alice"));
        assertTrue(testSecretKeys.containsKey("bob"));
        assertFalse(testSecretKeys.containsKey("boo"));
        assertEquals("YWxpY2U=", new String(testSecretKeys.get("alice")));
        assertEquals("Ym9iCg==", new String(testSecretKeys.get("bob")));
    }

    private void prepareTestFile() {
        // Check if the test file exists
        File testuserFile = new File("src/test/java/activities/test_users.txt");
        File testsecretFile = new File("src/test/java/activities/test_secret_keys.txt");
        if (testuserFile.exists()) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(testuserFile))) {
                writer.print("");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try (PrintWriter writer = new PrintWriter(new FileWriter("src/test/java/activities/test_users.txt"))) {
            writer.println("testUser1 " + encodeBase64("salt1") + " " + encodeBase64("hashedPassword1"));
            writer.println("testUser2 " + encodeBase64("salt2") + " " + encodeBase64("hashedPassword2"));
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (testsecretFile.exists()) {
            try (PrintWriter writer = new PrintWriter(new FileWriter(testsecretFile))) {
                writer.print("");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        try (PrintWriter writer = new PrintWriter(new FileWriter("src/test/java/activities/test_secret_keys.txt"))) {
            writer.println("alice:" + encodeBase64("YWxpY2U="));
            writer.println("bob:" + encodeBase64("Ym9iCg=="));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String encodeBase64(String input) {
        return Base64.getEncoder().encodeToString(input.getBytes());
    }

    @Test
    public void testHashPasswordSalt() {
        String password = "password123";
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        byte[] hashedPassword = Server.hashPasswordSalt(password, salt);
        assertNotNull(hashedPassword);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(salt);
            byte[] expectedHash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            assertArrayEquals(expectedHash, hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }

    @Test
    public void testVerifyPassword() {
        byte[] providedPasswordHash = "hash1".getBytes();
        byte[] storedPasswordHash = "hash1".getBytes();
        byte[] differentPasswordHash = "HAA".getBytes();
        assertTrue(Server.verifyPassword(providedPasswordHash, storedPasswordHash));
        assertFalse(Server.verifyPassword(providedPasswordHash, differentPasswordHash));
    }

    @Test
    public void testEncryptSecretKey() {
        try {
            byte[] secretKey = "mySecretKey".getBytes();
            byte[] passwordHash = "myPasswordHash".getBytes();
            byte[] trimmedPasswordHash = Arrays.copyOf(passwordHash, 16);
            SecretKeySpec secretKeySpec = new SecretKeySpec(trimmedPasswordHash, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] encryptedSecretKeyExpected = cipher.doFinal(secretKey);
            byte[] encryptedSecretKeyActual = Server.encryptSecretKey(secretKey, passwordHash);

            // Compare
            assertArrayEquals(encryptedSecretKeyExpected, encryptedSecretKeyActual);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            fail("Exception occurred during encryption: " + e.getMessage());
        }
    }

    @Test
    public void testDecryptSecretKey() {
        byte[] secretKey = "MySecretKey".getBytes(StandardCharsets.UTF_8);
        byte[] password = "MyPassword".getBytes(StandardCharsets.UTF_8);
        byte[] encryptedSecretKey = Server.encryptSecretKey(secretKey, password);
        byte[] decryptedSecretKey = Server.decryptSecretKey(encryptedSecretKey, password);
        assertArrayEquals(secretKey, decryptedSecretKey);
    }

    // @Test
    // public void testAuthenticationWithIncorrectCredentials() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
    //     // Simulate client sending correct username and password to the server
    //     // For simplicity, assume a mock client is used for testing
    //     try {
    //         ServerSocket serverSocket = new ServerSocket(port);
    //         Socket clientSocket = new Socket("localhost", port); // Assuming server is running on localhost and port 12345
    //         DataInputStream dataInputStream = new DataInputStream(clientSocket.getInputStream());
    //         DataOutputStream dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
    //         FileEncryption fe = new FileEncryption();

    //         SecretKey sk = fe.getAESKey();
    //         byte[] keyData =  sk.getEncoded();
    //         dataOutputStream.write(keyData);

    //         // Send username and password
    //         EncryptedCom.sendMessage("alice".getBytes(), sk, fe, dataOutputStream); 
    //         EncryptedCom.sendMessage("pass1234".getBytes(), sk, fe, dataOutputStream); 
    //         // Receive authentication response from the server
    //         byte[] responseByte = EncryptedCom.receiveMessage(sk, fe, dataInputStream);
    //         String response = new String(responseByte, StandardCharsets.UTF_8);
    //         assertEquals("Invalid username or password.", response);

    //         // Close the client socket
    //         serverSocket.close();
    //         clientSocket.close();
    //         dataInputStream.close();
    //         dataOutputStream.close();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //         fail("Connection failed: " + e.getMessage());
    //     }
    // }

    // @Test
    // public void testAuthenticationWithCorrectCredentials() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidAlgorithmParameterException {
    //     // Simulate client sending correct username and password to the server
    //     // For simplicity, assume a mock client is used for testing
    //     try {
    //         ServerSocket serverSocket = new ServerSocket(port);
    //         Socket clientSocket = new Socket("localhost", port); // Assuming server is running on localhost and port 12345
    //         DataInputStream dataInputStream = new DataInputStream(clientSocket.getInputStream());
    //         DataOutputStream dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
    //         FileEncryption fe = new FileEncryption();

    //         SecretKey sk = fe.getAESKey();
    //         byte[] keyData =  sk.getEncoded();
    //         dataOutputStream.write(keyData);

    //         // Send username and password
    //         EncryptedCom.sendMessage("bob".getBytes(), sk, fe, dataOutputStream); 
    //         EncryptedCom.sendMessage("secret456".getBytes(), sk, fe, dataOutputStream); 
    //         // Receive authentication response from the server
    //         byte[] responseByte = EncryptedCom.receiveMessage(sk, fe, dataInputStream);
    //         String response = new String(responseByte, StandardCharsets.UTF_8);
    //         assertEquals("Authentication successful. Proceeding with connection...", response);

    //         // Close the client socket
    //         serverSocket.close();
    //         clientSocket.close();
    //         dataInputStream.close();
    //         dataOutputStream.close();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //         fail("Connection failed: " + e.getMessage());
    //     }
    // }
    // @Test
    // public void testFileCommands() {
    //     // Simulate client sending correct username and password to the server
    //     // For simplicity, assume a mock client is used for testing
    //     try {
    //         Socket clientSocket = new Socket("localhost", 12345); // Assuming server is running on localhost and port 12345
    //         PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
    //         BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
    //         // Send username and password
    //         out.println("bob"); 
    //         out.println("secret456"); 
    //         // Receive authentication response from the server
    //         String response = in.readLine();
    //         // Verify that the server authenticates the user successfully
    //         //assertEquals("Authentication successful. Proceeding with connection...", response);
    //         assertEquals("Invalid username or password.", response);
    //         // Close the client socket
    //         clientSocket.close();
    //         in.close();
    //         out.close();
    //         clientSocket.close();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //         fail("Connection failed: " + e.getMessage());
    //     }
}

    // @Before
    // public void setUp() {
    //     // Initialize the server
    //     server = new Server();
    //     // Start the server in a separate thread
    //     Thread serverThread = new Thread(() -> Server.main(null));
    //     serverThread.start();
    //     // Allow some time for the server to start
    //     try {
    //         Thread.sleep(1000);
    //     } catch (InterruptedException e) {
    //         e.printStackTrace();
    //     }
    //     // Initialize the client
    //     client = new Client();
    // }

//     // @Test
//     // public void testAuthenticationSuccess() {
//     //     // Test authentication with correct username and password
//     //     assertTrue(client.authenticate("alice", "password123"));
//     // }

//     // @Test
//     // public void testAuthenticationFailure() {
//     //     // Test authentication with incorrect username and password
//     //     assertFalse(client.authenticate("alice", "wrongpassword"));
//     // }

//     // @Test
//     // public void testCreateProject() {
//     //     // Test creating a project
//     //     assertTrue(client.createProject("new_project"));
//     // }

//     // @Test
//     // public void testListProjects() {
//     //     // Test listing projects
//     //     String projects = client.listProjects();
//     //     assertEquals("project1\nproject2\n", projects); // Assuming project1 and project2 are existing projects
//     // }

//     // @Test
//     // public void testSendFile() {
//     //     // Test sending a file
//     //     assertTrue(client.sendFile("test.txt"));
//     // }

//     // @Test
//     // public void testDownloadFile() {
//     //     // Test downloading a file
//     //     assertTrue(client.downloadFile("test.txt"));
//     // }

//     // @Test
//     // public void testDeleteFile() {
//     //     // Test deleting a file
//     //     assertTrue(client.deleteFile("test.txt"));
//     // }
