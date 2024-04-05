package activities;
import org.junit.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertFalse;

import java.io.*;
import java.net.*;

import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

import java.io.File;
import java.nio.file.Files;

import org.junit.Before;
import org.junit.Test;

import activities.Client;
import activities.Server;
import utils.*;

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
