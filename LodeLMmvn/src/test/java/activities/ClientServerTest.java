package activities;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

import java.io.*;
import java.lang.reflect.Field;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import org.junit.Test;

import utils.*;

import java.util.Arrays;

import com.opencsv.exceptions.CsvException;
import com.opencsv.exceptions.CsvValidationException;


public class ClientServerTest {
    private Server server;
    private Client client;
    // int port = 12345;
    int port = 53779;

    @Test
    public void aesEncryptDecryptTest1() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        FileEncryption fe = new FileEncryption();
        SecretKey aesKey = fe.getAESKey();
        String test = "hello";
        byte[] cipherText = fe.AESEncrypt(test.getBytes(), aesKey);
        byte[] iv = fe.getIV();
        assertTrue(!test.equals(new String(cipherText, StandardCharsets.UTF_8)));
        byte[] decryptedTextByte = fe.AESDecrypt(cipherText, aesKey, iv);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(test.equals(decryptedText));
    } 
    @Test
    public void aesEncryptDecryptTest2() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        FileEncryption fe = new FileEncryption();
        SecretKey aesKey = fe.getAESKey();
        String test = " ";
        byte[] cipherText = fe.AESEncrypt(test.getBytes(), aesKey);
        byte[] iv = fe.getIV();
        assertTrue(!test.equals(new String(cipherText, StandardCharsets.UTF_8)));
        byte[] decryptedTextByte = fe.AESDecrypt(cipherText, aesKey, iv);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(test.equals(decryptedText));
    } 
    @Test
    public void aesEncryptDecryptTest3() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        FileEncryption fe = new FileEncryption();
        SecretKey aesKey = fe.getAESKey();
        String test = "00000000000000000000000000000000000000000000000000000000000000000000000000";
        byte[] cipherText = fe.AESEncrypt(test.getBytes(), aesKey);
        byte[] iv = fe.getIV();
        assertTrue(!test.equals(new String(cipherText, StandardCharsets.UTF_8)));
        byte[] decryptedTextByte = fe.AESDecrypt(cipherText, aesKey, iv);
        String decryptedText = new String(decryptedTextByte, StandardCharsets.UTF_8);
        assertTrue(test.equals(decryptedText));
    } 

    @Test
    public void fileEncryptDecryptTest() throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException, IOException, NoSuchPaddingException, InvalidAlgorithmParameterException{
        String filename = "client_data/file.txt";
        File file = new File(filename);
        byte[] fileContent = Files.readAllBytes(file.toPath());
        String fileContent1 = new String(fileContent, StandardCharsets.UTF_8);
        FileEncryption fe = new FileEncryption();

        byte[] cipherText = fe.encryptFile(file);
        String cipherText1 = new String(cipherText, StandardCharsets.UTF_8);
        byte[] iv = fe.getIV();
        assertTrue(!fileContent1.equals(cipherText1));

        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(iv);
        fileOutputStream.write(cipherText);
        fileOutputStream.close();

        byte[] decryptedTextByte = fe.decryptFile(file);
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
        assertTrue(testuserData1.containsKey("emailHash"));
    }

    @Test
    public void testLoadUserPasswordsValuesTrue() {
        prepareTestFile();
        Map<String, Map<String, byte[]>> testuserPasswords = Server.testGetUserPasswords();
        
        Map<String, byte[]> testuserData1 = testuserPasswords.get("testUser1");
        assertTrue((encodeBase64("salt1")).equals(Base64.getEncoder().encodeToString(testuserData1.get("salt"))));
        assertTrue(Arrays.equals(Server.hashSalt("hashedPassword1", testuserData1.get("salt")), testuserData1.get("passwordHash")));
        assertTrue(Arrays.equals(Server.hashSalt("hashedemail1", testuserData1.get("salt")), testuserData1.get("emailHash")));

        Map<String, byte[]> testuserData2 = testuserPasswords.get("testUser2");
        assertTrue((encodeBase64("salt2")).equals(Base64.getEncoder().encodeToString(testuserData2.get("salt"))));
        assertTrue(Arrays.equals(Server.hashSalt("hashedPassword2", testuserData2.get("salt")), testuserData2.get("passwordHash")));
        assertTrue(Arrays.equals(Server.hashSalt("hashedemail2", testuserData2.get("salt")), testuserData2.get("emailHash")));

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
        assertFalse((encodeBase64("hashedPasswod3")).equals(Base64.getEncoder().encodeToString(testuserData2.get("passwordHash"))));
        assertFalse((encodeBase64("email1")).equals(Base64.getEncoder().encodeToString(testuserData2.get("emailHash"))));
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
            writer.println("testUser1 " + encodeBase64("salt1") + " " + encodeBase64("hashedPassword1") + " " + encodeBase64("hashedemail1"));
            writer.println("testUser2 " + encodeBase64("salt2") + " " + encodeBase64("hashedPassword2") + " " + encodeBase64("hashedemail2"));
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
    public void testHashSalt() {
        String password = "password123";
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        byte[] hashedPassword = Server.hashSalt(password, salt);
        assertNotNull(hashedPassword);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(salt);
            byte[] expectedHash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < 20000; i++) {
                digest.reset();
                expectedHash = digest.digest(expectedHash);
            }
            assertArrayEquals(expectedHash, hashedPassword);
        } catch (NoSuchAlgorithmException e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }

    // @Test
    // public void testVerifyPassword() {
    //     byte[] providedPasswordHash = "hash1".getBytes();
    //     byte[] storedPasswordHash = "hash1".getBytes();
    //     byte[] differentPasswordHash = "HAA".getBytes();
    //     assertTrue(Server.verifyPassword(providedPasswordHash, storedPasswordHash));
    //     assertFalse(Server.verifyPassword(providedPasswordHash, differentPasswordHash));
    // }

    // @Test
    // public void testEncryptSecretKey() {
    //     try {
    //         byte[] secretKey = "mySecretKey".getBytes();
    //         byte[] passwordHash = "myPasswordHash".getBytes();
    //         byte[] trimmedPasswordHash = Arrays.copyOf(passwordHash, 16);
    //         SecretKeySpec secretKeySpec = new SecretKeySpec(trimmedPasswordHash, "AES");
    //         Cipher cipher = Cipher.getInstance("AES");
    //         cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
    //         byte[] encryptedSecretKeyExpected = cipher.doFinal(secretKey);
    //         byte[] encryptedSecretKeyActual = Server.encryptSecretKey(secretKey, passwordHash);

    //         // Compare
    //         assertArrayEquals(encryptedSecretKeyExpected, encryptedSecretKeyActual);
    //     } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
    //         e.printStackTrace();
    //         fail("Exception occurred during encryption: " + e.getMessage());
    //     }
    // }

    // @Test
    // public void testDecryptSecretKey() {
    //     byte[] secretKey = "MySecretKey".getBytes(StandardCharsets.UTF_8);
    //     byte[] password = "MyPassword".getBytes(StandardCharsets.UTF_8);
    //     byte[] encryptedSecretKey = Server.encryptSecretKey(secretKey, password);
    //     byte[] decryptedSecretKey = Server.decryptSecretKey(encryptedSecretKey, password);
    //     assertArrayEquals(secretKey, decryptedSecretKey);
    // }



    // testing SimpleMailSender.java

    @Test
    public void testEmptyEmail() {
        String emptyEmail = "";
        assertTrue(emptyEmail.isEmpty());
    }

    @Test
    public void testNonEmptyEmail() {
        String nonEmptyEmail = "example@example.com";
        assertFalse(nonEmptyEmail.isEmpty());
    }

    @Test
    public void testValidEmail() {
        // Test valid email addresses
        assertTrue(SimpleMailSender.isValidEmail("test@example.com"));
        assertTrue(SimpleMailSender.isValidEmail("user123@gmail.com"));
        assertTrue(SimpleMailSender.isValidEmail("john.doe@company.co"));
        assertTrue(SimpleMailSender.isValidEmail("user_123@example.com"));
        assertTrue(SimpleMailSender.isValidEmail("user-123@example.com"));
        assertTrue(SimpleMailSender.isValidEmail("user+123@example.com"));
    }

    @Test
    public void testInvalidEmail() {
        // Test invalid email addresses
        assertFalse(SimpleMailSender.isValidEmail("test@example"));
        assertFalse(SimpleMailSender.isValidEmail("test@.com"));
        assertFalse(SimpleMailSender.isValidEmail("test"));
        assertFalse(SimpleMailSender.isValidEmail("test@.com"));
        assertFalse(SimpleMailSender.isValidEmail("test.com"));
        assertFalse(SimpleMailSender.isValidEmail("@example.com"));
    }

    @Test
    public void testGenerateOTP() {
        String otp = SimpleMailSender.generateOTP();
        // Assert that OTP has correct length, contains only uppercase letters, and digits
        assertEquals(6, otp.length());
        assertTrue(otp.matches("[A-Z0-9]+"));
    }



    // testing Client.java methods

    @Test
    public void testUserExists_WhenUserExistsTrue() {
        prepareTestFile();
        assertTrue(Client.UserExists("testUser1", "test"));
    }

    @Test
    public void testUserExistsFalse() {
        prepareTestFile();
        assertFalse(Client.UserExists("username", "test"));
    }

    @Test
    public void testUserEmailMatch() {
        prepareTestFile();
        // correct username and email
        assertTrue(Client.UserEmailMatch("testUser2", "hashedemail2", "test"));
        // incorrect username
        assertFalse(Client.UserEmailMatch("nonExistingUser", "hashedemail2", "test"));
        // incorrect email
        assertFalse(Client.UserEmailMatch("testUser2", "wrong@example.com", "test"));
        // null username
        assertFalse(Client.UserEmailMatch(null, "hashedemail2", "test"));
    }

    @Test
    public void testIsPasswordStrong() {
        assertTrue(Client.isPasswordStrong("Password123#"));
        assertFalse(Client.isPasswordStrong("pass#"));
        assertFalse(Client.isPasswordStrong("Password#"));
        assertFalse(Client.isPasswordStrong("password123#"));
        assertFalse(Client.isPasswordStrong("PASSWORD123#"));
        assertFalse(Client.isPasswordStrong("Password123"));
        assertFalse(Client.isPasswordStrong("Password1234"));
    }
    
    @Test
    public void testlogAuditAction() throws IOException {
        String username = "username";
        String permission = "normal";
        String action = "login";
        String filename = "testlog.txt";

        Client.logAuditAction(username, permission, action, filename);
        String log;

        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append(System.lineSeparator());
            }
            log = content.toString();
        } catch (IOException e) {
            fail("Failed to read log file: " + e.getMessage());
            log = "null";
        }

        String expectedLogEntry = String.format("%s,%s,%s,%s", username, permission, 
        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")), action);
        
        assertTrue("Log entry not found in the log file", log.contains(expectedLogEntry));

    }



    @Test
    public void testAuditLog() {
        // Ensure the audit log file is empty before the test
        File auditLogFile = new File("test_audit_log.txt");
        if (auditLogFile.exists()) {
            auditLogFile.delete();
        }

        // Mock login action
        String username = "testUser";
        String permissionLevel = "admin";
        String action = "Login";
        FileHandler.logAuditAction(username, permissionLevel, action, "test_audit_log.txt");

        // Check if the audit log file has been created and contains the login action
        assertTrue(auditLogFile.exists());

        try (BufferedReader reader = new BufferedReader(new FileReader(auditLogFile))) {
            String logEntry = reader.readLine();
            assertNotNull(logEntry);

            // Verify if the log entry contains the correct information
            assertTrue(logEntry.contains(username));
            assertTrue(logEntry.contains(permissionLevel));
            assertTrue(logEntry.contains(action));
        } catch (IOException e) {
            fail("Exception occurred: " + e.getMessage());
        }
    }



    // test FileEncryption

    @Test
    public void testSaveKey() throws IOException, NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretkey = keyGenerator.generateKey();
        File tempFile = File.createTempFile("testkey", ".txt");
        FileEncryption.saveKey(secretkey, tempFile);
        byte[] encodedKeyBytes = Files.readAllBytes(Paths.get(tempFile.getAbsolutePath()));
        String encodedKeyString = new String(encodedKeyBytes);
        byte[] decodedKeyBytes = java.util.Base64.getDecoder().decode(encodedKeyString);
        SecretKey savedKey = new javax.crypto.spec.SecretKeySpec(decodedKeyBytes, "AES");
        assertTrue(tempFile.exists());
        assertEquals(secretkey, savedKey);
        tempFile.delete();
    }

    @Test
    public void testGethmacKey() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        FileEncryption fe = new FileEncryption();
        SecretKey hmacKey = fe.getHmacKey();
        assertNotNull(hmacKey);
        assertEquals("HmacSHA256", hmacKey.getAlgorithm());
        assertEquals(32, hmacKey.getEncoded().length);
    }



    // testing MACUtils

    @Test
    public void testCreateMAC() throws InvalidKeyException, NoSuchAlgorithmException {

        byte[] data = "test".getBytes();
        byte[] key = "secret".getBytes();
        byte[] mac = MACUtils.createMAC(data, key);

        byte[] emptydata = new byte[0];
        byte[] emptyDatamac = MACUtils.createMAC(emptydata, key);
        byte[] invalidkey = new byte[10];
        byte[] MACinvalidKey = MACUtils.createMAC(data, invalidkey);

        assertNotNull(mac);
        assertNotNull(emptyDatamac);
        assertNotNull(MACinvalidKey);

        Mac testMac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(key, "HmacSHA256");
        testMac.init(secretKey);
        byte[] expectedMAC = testMac.doFinal(data);
        assertArrayEquals(expectedMAC,mac);
    }

    @Test
    public void testCreateMACWithInvalidKey() {
        byte[] data = "test".getBytes();
        byte[] invalidKey = new byte[0];
        assertThrows(IllegalArgumentException.class, () -> {
            MACUtils.createMAC(data, invalidKey);
        });
    }

    @Test
    public void testcreateMACBase64() {
        byte[] data = "test".getBytes();
        byte[] key = "secret".getBytes();
        String MAC64str = MACUtils.createMACBase64(data, key);
        byte[] mac = MACUtils.createMAC(data, key);
        assertTrue(Base64.getEncoder().encodeToString(mac).equals(MAC64str));
    }

    @Test
    public void testverifyMAC() {
        byte[] data = "test".getBytes();
        byte[] key = "secret".getBytes();
        byte[] mac = MACUtils.createMAC(data, key);
        assertTrue(MACUtils.verifyMAC(data, mac, key));
    }



    // testing FileHandler

    @Test
    public void testSendFile_PermissionFail() throws CsvValidationException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException{
        String path = "testFile.txt";
        String username = "testUser";
        File tempFile = new File(path);
        String tempContent = "testing send file.";
        Files.write(tempFile.toPath(), tempContent.getBytes());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        FileHandler fileHandler = new FileHandler(path);
        SecretKey commKey = new SecretKeySpec("testKey".getBytes(), "AES");
        boolean isServer = true;

        String result = fileHandler.sendFile(dataOutputStream, commKey, isServer, username);
        assertEquals("You do not have the required permissions to download this file.", result);
        tempFile.delete();
    }

    @Test
    public void testSendFile_ServerPass() throws CsvValidationException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException{
        String path = "server_data/test.txt";
        String username = "alice";

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        FileHandler fileHandler = new FileHandler(path);
        SecretKey commKey = new SecretKeySpec("testKey".getBytes(), "AES");
        boolean isServer = true;

        String result = fileHandler.sendFile(dataOutputStream, commKey, isServer, username);
        assertEquals("File Downloaded", result);
    }

    @Test
    public void testSendFile_ClientPass() throws CsvValidationException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException{
        String path = "testFile.txt";
        String username = "testUser";
        SecretKey commKey = new SecretKeySpec("testKey".getBytes(), "AES");
        boolean isServer = false;

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        File tempFile = new File(path);
        String tempContent = "testing send file.";
        Files.write(tempFile.toPath(), tempContent.getBytes());
        FileHandler fileHandler = new FileHandler(path);

        String result = fileHandler.sendFile(dataOutputStream, commKey, isServer, username);
        assertEquals("File Downloaded", result);
        tempFile.delete();
    }

    @Test
    public void testpwd() {
        String path = "testFile.txt";
        FileHandler fileHandler = new FileHandler(path);
        String currentDirectory = new File("").getAbsolutePath();
        currentDirectory = "Working Directory: " + currentDirectory + "/testFile.txt";
        assertEquals(currentDirectory, fileHandler.pwd());
    }

    @Test
    public void testListFiles() {
        String path = "tempDir";
        File tempDir = new File(path);
        tempDir.mkdir();
        File file1 = new File(tempDir, "file1.txt");
        File file2 = new File(tempDir, "file2.txt");
        try {
            file1.createNewFile();
            file2.createNewFile();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        FileHandler fileHandler = new FileHandler(path);

        String expectedString = "Files in the directory: file2.txt file1.txt ";
        assertEquals(expectedString, fileHandler.listFiles());

        file1.delete();
        file2.delete();
        tempDir.delete();
    }

    @Test
    public void testDeleteFile() throws IOException, CsvValidationException, CsvException {
        String path = "testFile.txt";
        String username = "testUser";
        File tempFile = new File(path);
        String tempContent = "testing send file.";
        Files.write(tempFile.toPath(), tempContent.getBytes());
        FileHandler fileHandler = new FileHandler(path);

        String result = fileHandler.deleteFile(username);
        assertEquals("testFile.txt was deleted", result);
        tempFile.delete();
    }

    // @Test
    // public void testReceiveFile() throws Exception {
    //     String path = "testFile.txt";
    //     String username = "testUser";
    //     String tempContent = "testing file.";

    //     File tempFile = new File(path);

    //     ByteArrayInputStream inputStream = new ByteArrayInputStream(tempContent.getBytes());
    //     DataInputStream dataInputStream = new DataInputStream(inputStream);
    //     FileHandler fileHandler = new FileHandler(path);
    //     SecretKey commKey = new SecretKeySpec("testKey".getBytes(), "AES");
    //     boolean isServer = true;

    //     // Invoke method
    //     String result = fileHandler.receiveFile(dataInputStream, commKey, isServer, username);

    //     // Verify output
    //     assertEquals("null", result);
    //     // String result = fileHandler.sendFile(dataOutputStream, commKey, isServer, username);
    //     // assertEquals("You do not have the required permissions to download this file.", result);

    //     tempFile.delete();
    // }

    @Test
    public void testReceiveFile_Success() throws Exception {
        // Prepare test data
        String path = "testFile.txt";
        String username = "testUser";
        String tempContent = "testing send file.";

        // Create a temporary file with test data
        try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
            fileOutputStream.write(tempContent.getBytes());
        }

        // Prepare other input parameters
        ByteArrayInputStream inputStream = new ByteArrayInputStream(tempContent.getBytes());
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        SecretKey commKey = new SecretKeySpec("testKey".getBytes(), "AES");
        boolean isServer = true;

        // Call the method
        FileHandler fileHandler = new FileHandler(path);
        String result = fileHandler.receiveFile(dataInputStream, commKey, isServer, username);

        // Assert the result
        assertEquals(null, result);

        // Clean up temporary resources
        dataInputStream.close();
        File tempFile = new File(path);
        tempFile.delete();
    }



    // testing ClientHandler methods

    @Test
    public void testCreateAndUpdateAccount() throws IOException {
        String username = "testUser";
        byte[] password = "testPassword".getBytes(StandardCharsets.UTF_8);
        byte[] newPassword = "testNewPassword".getBytes(StandardCharsets.UTF_8);
        String email = "testEmail";
        ClientHandler.createAccount(username, password, email);
        // check after instantiating new account
        try {
            Field userPasswordsField = Server.class.getDeclaredField("userPasswords");
            userPasswordsField.setAccessible(true);
            Map<String, Map<String,byte[]>> userPasswords = (Map<String, Map<String,byte[]>>) userPasswordsField.get(null);
            assertTrue(userPasswords.containsKey(username));
            Map<String, byte[]> userData = userPasswords.get(username);
            assertNotNull(userData);
            // check keys
            assertTrue(userData.containsKey("salt"));
            assertTrue(userData.containsKey("passwordHash"));
            assertTrue(userData.containsKey("emailHash"));
            // check value
            String storedpwdhash = Base64.getEncoder().encodeToString(userData.get("passwordHash"));
            byte[] calculatedpwdhash = Server.hashSalt("testPassword", userData.get("salt"));
            String strcalculatedpwdhash = Base64.getEncoder().encodeToString(calculatedpwdhash);
            assertTrue((storedpwdhash).equals(strcalculatedpwdhash));

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(outputStream);
            System.setOut(printStream);
            ClientHandler.resetPassword("bbbbbbbbbbb", newPassword, email);
            String consoleOutput = outputStream.toString();
            assertTrue(consoleOutput.contains("User does not exist."));
            ClientHandler.resetPassword(username, newPassword, email);
            // check after updating account
            // check keys
            assertTrue(userData.containsKey("salt"));
            assertTrue(userData.containsKey("passwordHash"));
            assertTrue(userData.containsKey("emailHash"));
            // check value
            String newsalt = Base64.getEncoder().encodeToString(userData.get("salt"));
            String newstoredpwdhash = Base64.getEncoder().encodeToString(userData.get("passwordHash"));
            byte[] newcalculatedpwdhash = Server.hashSalt(new String(newPassword, StandardCharsets.UTF_8), userData.get("salt"));
            String newstrcalculatedpwdhash = Base64.getEncoder().encodeToString(newcalculatedpwdhash);
            assertTrue((newstoredpwdhash).equals(newstrcalculatedpwdhash));

        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to access private field: " + e.getMessage());
        }

        // deleting this testuser from userData, secret_key, and users file
        try {
            Field userPasswordsField = Server.class.getDeclaredField("userPasswords");
            userPasswordsField.setAccessible(true);
            Map<String, Map<String, byte[]>> userPasswords = (Map<String, Map<String, byte[]>>) userPasswordsField.get(null);
            userPasswords.remove("testUser");
        } catch (NoSuchFieldException | IllegalAccessException e) {
            fail("Failed to access private field: " + e.getMessage());
        }
        removeTestUserFromFile();
        removeTestUserFromSecretFile();
    }

    public static void removeTestUserFromFile() {
        String userPath = System.getProperty("user.dir") + "/server_data/users.txt";
        File usersFile = new File(userPath);
        File tempFile = new File("src/main/java/activities/users_temp.txt");
    
        try (BufferedReader reader = new BufferedReader(new FileReader(usersFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
            String line;
            boolean isFirstLine = true;
            while ((line = reader.readLine()) != null) {
                if (!line.contains("testUser")) {
                    if (!isFirstLine) {
                        writer.newLine(); 
                        // Add new line only if it's not the first line
                    } else {
                        isFirstLine = false;
                    }
                    writer.write(line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    
        // Replace the original file with the temporary file
        try {
            Files.move(tempFile.toPath(), usersFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void removeTestUserFromSecretFile() throws IOException {
        File usersFile = new File("src/main/java/activities/secret_keys.txt");
        File tempFile = new File("src/main/java/activities/secret_keys_temp.txt");
    
        try (BufferedReader reader = new BufferedReader(new FileReader(usersFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.contains("testUser")) {
                    writer.write(line + System.lineSeparator());
                }
            }
        }
        Files.move(tempFile.toPath(), usersFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    // this tests most of the other dependant methods



    // testing EncryptedCom

    @Test
    public void testRSAEncryptAndDecrypt() throws Exception {
        // Generate RSA key pair for testing
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] originalData = "Hello, World!".getBytes();

        byte[] encryptedData = EncryptedCom.RSAEncrypt(originalData, publicKey);
        byte[] decryptedData = EncryptedCom.decryptRSA(encryptedData, (RSAPrivateKey) privateKey);

        assertArrayEquals(originalData, decryptedData);
    }

    @Test
    public void testSendMessageAndReceiveMessage() throws Exception {
        FileEncryption fe = new FileEncryption();
        SecretKey aesKey = fe.getAESKey();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        byte[] originalData = "Hello, World!".getBytes();

        EncryptedCom.sendMessage(originalData, aesKey, fe, dataOutputStream);
        byte[] encryptedMessage = outputStream.toByteArray();

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encryptedMessage);
        DataInputStream dataInputStream = new DataInputStream(inputStream);
        byte[] decryptedData = EncryptedCom.receiveMessage(aesKey, fe, dataInputStream);

        assertArrayEquals(originalData, decryptedData);
    }
}