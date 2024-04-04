package utils;

import java.io.*;
import java.security.*;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

public class EncryptedCom {
    public static int MAX_BUFFER_SIZE = 4096;

    public static void sendMessage(String text, SecretKey aesKey, FileEncryption fe, DataOutputStream dataOutputStream) throws InvalidAlgorithmParameterException, IOException, InvalidKeyException {
        try {
            // Implement encryption here
            byte[] byteText = text.getBytes();
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

    public static String receiveMessage(SecretKey aesKey, FileEncryption fe, DataInputStream dataInputStream) {
        try {
            byte[] iv_cipher = new byte[16];
            dataInputStream.read(iv_cipher, 0, 16);
            
            long size = dataInputStream.readLong();
            int max_bytes = (int) Math.min(MAX_BUFFER_SIZE, size);
            byte[] buffer = new byte[max_bytes];
            dataInputStream.read(buffer, 0, max_bytes);

            // Decrypt
            byte[] text = fe.AESDecrypt(buffer, aesKey, iv_cipher);
            String message = new String(text, StandardCharsets.UTF_8);
            return message; 
        } catch (Exception e) {
            System.out.println(e);
        }
        return "";
    }
}