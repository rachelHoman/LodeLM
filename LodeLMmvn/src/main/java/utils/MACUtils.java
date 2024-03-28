package app.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

public class MACUtils {
    public static byte[] createMAC(byte[] data, byte[] key) {
        try {
            // Create a Mac instance with HMAC-SHA-256 algorithm
            Mac mac = Mac.getInstance("HmacSHA256");

            // Create a SecretKeySpec with the provided key and algorithm
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");

            // Initialize the Mac with the key
            mac.init(secretKeySpec);

            // Calculate the MAC
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String createMACBase64(byte[] data, byte[] key) {
        // Create the MAC
        byte[] macBytes = createMAC(data, key);

        // Encode the MAC bytes to Base64 for easy transmission
        return Base64.getEncoder().encodeToString(macBytes);
    }

    public static boolean verifyMAC(byte[] data, byte[] mac, byte[] key) {
        try {
            // Create a Mac instance with HMAC-SHA-256 algorithm
            Mac macInstance = Mac.getInstance("HmacSHA256");

            // Create a SecretKeySpec with the provided key and algorithm
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA256");

            // Initialize the Mac with the key
            macInstance.init(secretKeySpec);

            // Calculate the MAC for the data
            byte[] calculatedMac = macInstance.doFinal(data);

            // Compare the calculated MAC with the provided MAC
            return Arrays.equals(calculatedMac, mac);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return false;
        }
    }
}

