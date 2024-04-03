package utils;

import java.io.*;
import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

import java.io.FileWriter;
import java.util.Base64;

import com.opencsv.CSVWriter;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

public class FileHandler {
    String path;

    /***
     * Constructor for FileHandler
     * 
     * String path: the path name of the file to be either sent, saved, or deleted 
     */
    public FileHandler (String path) {
        this.path = path;
    }

    /***
     * Reads the file's contents via an input stream then sends file via the given output stream
     * 
     * DataOutputStream dataOutputStream: the output stream to write the file into
     * 
     * return: none
     */
    public void sendFile(DataOutputStream dataOutputStream, boolean isServer) throws CsvValidationException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        int bytes = 0;
        File file = new File(this.path);

        if (isServer) {
            // Decrypt the file before sending to client
            FileEncryption fe = new FileEncryption();
            String[] fileDecryptInfo = this.retrieveFileKeyCSV();

            if (fileDecryptInfo != null && fileDecryptInfo.length == 2) {
                // Decode the base64 encoded string
                byte[] decodedKey = Base64.getDecoder().decode(fileDecryptInfo[1]);
                // Rebuild key using SecretKeySpec
                SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); 
                byte[] text = fe.decryptFile(file, key);

                dataOutputStream.writeLong(text.length);
                dataOutputStream.write(text, 0, text.length);

                dataOutputStream.flush();
            } else {
                System.out.println("Decryption Error");
            }
        }
        else {
            FileInputStream fileInputStream = new FileInputStream(file);

            // Read in file and write to destination
            dataOutputStream.writeLong(file.length());
            byte[] buffer = new byte[4096];
            while ((bytes = fileInputStream.read(buffer)) != -1) {
                dataOutputStream.write(buffer, 0, bytes);
            }
            dataOutputStream.flush();
            fileInputStream.close();
        }
    }

    /***
     * Receives file via the given input stream and writes it to the output stream
     * 
     * DataInputStream dataInputStream: the input stream to read in the file through
     * 
     * return: none
     */
    public void receiveFile(DataInputStream dataInputStream, boolean isServer) throws NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        
        int bytes = 0;
        FileOutputStream fileOutputStream = new FileOutputStream(this.path);
 
        // Read file in
        long size = dataInputStream.readLong();
        byte[] buffer = new byte[4096];
        int max_bytes = (int) Math.min(buffer.length, size);
        while (size > 0 && (bytes = dataInputStream.read(buffer, 0, max_bytes))!= -1) {
            fileOutputStream.write(buffer, 0, bytes);
            size -= bytes;
            max_bytes = (int) Math.min(buffer.length, size);
        }

        if (isServer) {
            // Encrypt file
            FileEncryption fe = new FileEncryption();
            File file = new File(this.path);
            byte[] cipherText = fe.encryptFile(file);
            byte[] iv = fe.getIV();
            SecretKey sk = fe.getSK();

            FileOutputStream outputStream = new FileOutputStream(file);
            outputStream.write(iv);
            outputStream.write(cipherText);
            outputStream.close();

            // Store file decryption info
            String encodedKey = Base64.getEncoder().encodeToString(sk.getEncoded());
            String [] fileKeyInfo = {this.path, encodedKey};
            this.appendFileKeyCSV(fileKeyInfo);
        }
        fileOutputStream.close();
    }

    /***
     * Deletes file and send message to requester if the file does not exist.
     * 
     * return: (boolean) whether or not the file was deleted
     */
    public boolean deleteFile() {
        File file = new File(this.path);
        boolean deleted = file.delete();
        return deleted;
    }

    /***
     * Outputs current working directory
     * 
     * return: (String) output to print to user
     */
    public String pwd() {
        String output = "Working Directory: " + System.getProperty("user.dir") + "/" + this.path;
        return output;
    }

    /***
     * Lists files in server directory
     * 
     * return: (String) output to print to user
     */
    public String listFiles() {
        File directory = new File(this.path);

        File[] files = directory.listFiles();

        String output;
        if (directory.isDirectory()) {
            // Check if there are files in the directory
            if (files != null) {
                output = "Files in the directory: ";
                for (File file : files) {
                    output += file.getName() + " ";
                }
            } else {
                output = "No files in the directory.";
            }
        } else {
            output = "The path you provided is not a directory";
        }
        return output;
    }

    public void appendFileKeyCSV(String[] fileKeyInfo) throws IOException {
        String csv = "server_data/file_keys.csv";
        CSVWriter writer = new CSVWriter(new FileWriter(csv, true));
        writer.writeNext(fileKeyInfo);
        writer.close();
    }

    public String[] retrieveFileKeyCSV() throws IOException, CsvValidationException {
        String csv = "server_data/file_keys.csv";
        try {
            FileReader filereader = new FileReader(csv); 
        
            CSVReader csvReader = new CSVReader(filereader); 
            String[] nextRecord; 
  
            // we are going to read data line by line 
            while ((nextRecord = csvReader.readNext()) != null) { 
                if (nextRecord.length > 0 && nextRecord[0].equals(this.path)) {
                    return nextRecord;
                }
            }
        }
        catch (IOException io) {
            System.out.println(io);
        }
        System.out.println("File Access Denied");
        return null;
    }
}