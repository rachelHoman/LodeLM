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
import java.io.File;
import java.nio.file.Files;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileEncryption {

    //instance variables
	private final int AES_KEY_LENGTH = 256;
	private final int MAC_KEY_LENGTH = 256;
	private final String MAC_HASH = "HmacSHA256";

    SecretKey sk;
    byte[] iv = null;

    public FileEncryption () {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] getIV() {
        return this.iv;
    }

    public SecretKey getSK() {
        return this.sk;
    }

    public byte[] encryptFile(File file) throws IOException, FileNotFoundException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] fileContent = Files.readAllBytes(file.toPath());
        this.sk = this.getAESKey();
        byte[] cipherText = this.AESEncrypt(fileContent, this.sk);
        return cipherText;
    }

    public byte[] decryptFile(File file, SecretKey key) throws IOException, FileNotFoundException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] fileContent = Files.readAllBytes(file.toPath());
        byte[] iv_cipher = Arrays.copyOfRange(fileContent, 0, 16);
        fileContent = Arrays.copyOfRange(fileContent, 16, fileContent.length);
        byte[] cipherText = this.AESDecrypt(fileContent, key, iv_cipher);
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