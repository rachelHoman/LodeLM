package utils;

import java.io.*;
import java.util.Arrays;

import java.security.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;

import java.util.Base64;

import org.apache.commons.io.FileUtils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileEncryption {

    //instance variables
	private final int AES_KEY_LENGTH = 256;
	private final int MAC_KEY_LENGTH = 256;
	private final String MAC_HASH = "HmacSHA256";

    private final File SERVER_KEY_FILE = new File("/workspaces/LodeLM/file_keys.csv");

    private SecretKey sk;
    byte[] iv = null;

    public FileEncryption () throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        this.sk = loadKey(this.SERVER_KEY_FILE);
    }

    public byte[] getIV() {
        return this.iv;
    }

    public byte[] encryptFile(File file) throws IOException, FileNotFoundException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] fileContent = Files.readAllBytes(file.toPath());
        byte[] cipherText = this.AESEncrypt(fileContent, this.sk);
        return cipherText;
    }

    public byte[] decryptFile(File file) throws IOException, FileNotFoundException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] fileContent = Files.readAllBytes(file.toPath());
        byte[] iv_cipher = Arrays.copyOfRange(fileContent, 0, 16);
        fileContent = Arrays.copyOfRange(fileContent, 16, fileContent.length);
        byte[] cipherText = this.AESDecrypt(fileContent, this.sk, iv_cipher);
        return cipherText;
    }


    public byte[] AESEncrypt(byte[] text, SecretKey key) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");

		//generate random iv
		SecureRandom randomSecureRandom = new SecureRandom();
		this.iv = new byte[cipher.getBlockSize()];
		randomSecureRandom.nextBytes(this.iv);
		IvParameterSpec ivParams = new IvParameterSpec(this.iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);
		byte[] encryptedText = cipher.doFinal(text);
        return encryptedText;
	}

    public byte[] AESDecrypt(byte[] cipherText, SecretKey key, byte[] iv_cipher) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		IvParameterSpec ivParams = new IvParameterSpec(iv_cipher);
        cipher.init(Cipher.DECRYPT_MODE, key, ivParams);
        byte[] decryptedText = cipher.doFinal(cipherText);
        return decryptedText;
    }

    /***
     * Generates AES Key for file confidentiality
     * 
     * Return (SecretKey) AES Key
     */
    public SecretKey getAESKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
		keyGen.init(AES_KEY_LENGTH); 
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}

    public static void saveKey(SecretKey key, File file) throws IOException {
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        BufferedWriter bufferedWriter = new BufferedWriter (new FileWriter (file));
        bufferedWriter.write(encodedKey);
        bufferedWriter.close();
    }

    public static SecretKey loadKey(File file) throws IOException {
        byte[] fileBytes = FileUtils.readFileToByteArray(file);
        byte[] decodedKey = Base64.getDecoder().decode(fileBytes);
        // Rebuild key using SecretKeySpec
        SecretKey fileKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
        return fileKey;
    }

    /***
     * Generates HMAC Key for Integrity of the file
     * 
     * Return (SecretKey) HMAC Key
     */
    public SecretKey getHmacKey() throws NoSuchAlgorithmException, InvalidKeyException {
		KeyGenerator keyGen = KeyGenerator.getInstance(MAC_HASH);
		keyGen.init(MAC_KEY_LENGTH);
		SecretKey secretKey = keyGen.generateKey();
		return secretKey;
	}
}