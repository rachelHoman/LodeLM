package utils;

import java.util.Arrays;

import java.io.*;
import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.PSource;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

public class EncryptedCom {
    public static int MAX_BUFFER_SIZE = 4096;
    private static final String MAC_HASH = "HmacSHA256";

    public static byte[] RSAEncrypt(byte[] text, PublicKey key) throws Exception {
		byte[] cipherText = null;

        //get an RSA cipher object and print the provider
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, key, oaepParams);

        //encrypt the plaintext
        cipherText = cipher.doFinal(text);
        return cipherText;
    }

    public static byte[] decryptRSA(byte[] text, RSAPrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        byte[] decryptedText = null;
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        decryptedText = cipher.doFinal(text);
        return decryptedText;
    }

    public static void sendMessage(byte[] byteText, SecretKey aesKey, FileEncryption fe, DataOutputStream dataOutputStream) throws InvalidAlgorithmParameterException, IOException, InvalidKeyException {
        try {
            // Implement encryption here
            byte[] cipherText = fe.AESEncrypt(byteText, aesKey);
            byte[] iv_cipher = fe.getIV();
            dataOutputStream.write(iv_cipher);
            dataOutputStream.writeLong(cipherText.length);
            dataOutputStream.write(cipherText);
            dataOutputStream.flush();
        }
        catch (Exception e) { 
            System.out.println(e);
        }
        return; 
    }

    public static byte[] receiveMessage(SecretKey aesKey, FileEncryption fe, DataInputStream dataInputStream) {
        try {
            byte[] iv_cipher = new byte[16];
            dataInputStream.read(iv_cipher, 0, 16);
            
            long size = dataInputStream.readLong();
            int max_bytes = (int) Math.min(MAX_BUFFER_SIZE, size);
            byte[] buffer = new byte[max_bytes];
            dataInputStream.read(buffer, 0, max_bytes);

            // Decrypt
            byte[] textByte = fe.AESDecrypt(buffer, aesKey, iv_cipher);
        
            return textByte; 
        } catch (Exception e) {
            System.out.println(e);
        }
        return "".getBytes();
    }

}