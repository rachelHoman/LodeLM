package utils;

import java.io.*;
import java.util.List;

import java.security.*;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;

import java.io.FileWriter;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

import com.opencsv.CSVWriter;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvException;
import com.opencsv.exceptions.CsvValidationException;

import java.util.ArrayList;

public class FileHandler {
    String path;
    int MAX_BUFFER_SIZE = 4096;
    String csv = "/workspaces/LodeLM/user_permissions.csv";

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
     * return: (String) output for user
     */
    public String sendFile(DataOutputStream dataOutputStream, SecretKey commKey, boolean isServer, String username) throws CsvValidationException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        String userOutput = "File Downloaded";
        int bytes = 0;
        File file = new File(this.path);
        byte[] cipherText;
        FileEncryption fe = new FileEncryption();

        if (isServer) {
            // Decrypt the file before sending to client
            String[] filePermissionInfo = this.retrieveUserPermissionsCSV(username);

            if (filePermissionInfo != null && filePermissionInfo.length == 3 && filePermissionInfo[2].contains("r")) {
                byte[] text = fe.decryptFile(file);
                
                EncryptedCom.sendMessage(text, commKey, fe, dataOutputStream);
            } else {
                userOutput = "You do not have the required permissions to download this file.";
                EncryptedCom.sendMessage("cannot download".getBytes(), commKey, fe, dataOutputStream);
            }
            return userOutput;
        }
        else {
            FileInputStream fileInputStream = new FileInputStream(file);

            // Read in file and write to destination
            int max_bytes = (int) Math.min(MAX_BUFFER_SIZE, file.length());
            byte[] buffer = new byte[max_bytes];
            fileInputStream.read(buffer, 0, max_bytes);
            EncryptedCom.sendMessage(buffer, commKey, fe, dataOutputStream);
            fileInputStream.close();
        }
        // System.out.println(userOutput);
        return userOutput;
    }

    /***
     * Receives file via the given input stream and writes it to the output stream
     * 
     * DataInputStream dataInputStream: the input stream to read in the file through
     * 
     * return: none
     */
    public String receiveFile(DataInputStream dataInputStream, SecretKey commKey, boolean isServer, String username) throws CsvException, CsvValidationException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException, FileNotFoundException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        String outputString = null;

        // Read file in
        FileEncryption fe = new FileEncryption();
        byte[] fileContent = EncryptedCom.receiveMessage(commKey, fe, dataInputStream);
        if (new String(fileContent, StandardCharsets.UTF_8).equals("cannot download")) {
            return "";
        }

        int bytes = 0;

        if (isServer) {
            boolean appended = this.appendUserPermissionsCSV(username, null, "rw");
            if (!appended) {
                outputString = "You do not have permission to override the current file with that name on the server. Please change the name of your file.";
                return outputString;
            }

            // Encrypt file
            File file = new File(this.path);

            FileOutputStream fileOutputStream = new FileOutputStream(this.path);
            fileOutputStream.write(fileContent, 0, fileContent.length);

            byte[] cipherText = fe.encryptFile(file);
            byte[] iv = fe.getIV();

            FileOutputStream outputStream = new FileOutputStream(file);
            fileOutputStream.close();
            outputStream.write(iv);
            outputStream.write(cipherText);
            outputStream.close();

            // TODO: Store user permissions info
            // String encodedKey = Base64.getEncoder().encodeToString(sk.getEncoded());
        } else {
            FileOutputStream fileOutputStream = new FileOutputStream(this.path);
            fileOutputStream.write(fileContent, 0, fileContent.length);
            fileOutputStream.close();
        }
        return outputString;
    }

    /***
     * Deletes file and send message to requester if the file does not exist.
     * 
     * return: (String) whether or not the file was deleted
     */
    public String deleteFile(String username) throws IOException, CsvValidationException, CsvException {
        String userOutput = "File has not been deleted...either does not exist or something else went wrong.";
        File file = new File(this.path);
        // Check if the user has write privileges
        int row = this.searchUserPermissionsCSV(username);
        if (row != -1) {
            String[] userPermissionInfo = this.retrieveUserPermissionsCSV(username);
            if (userPermissionInfo != null && userPermissionInfo.length == 3 && userPermissionInfo[2].contains("w")) {
                boolean deleted = file.delete();
                if (deleted) {
                    ArrayList<Integer> rowList = this.searchFilenameCSV();
                    if (rowList.size() != 0) {
                        // Delete lines
                        System.out.println(rowList);
                        this.deleteFileCSV(rowList);
                    }
                    userOutput = this.path + " was deleted";
                }
            } else {
                userOutput = "You do not have the proper permissions to delete this file.";
            }
        }
        return userOutput;
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

    /***
     * Outputs current working directory
     * 
     * return: (String) output to print to user
     */
    public String shareFile(String username, String sharedUsername, String privileges) throws CsvException, IOException {
        String output = "File not shared for some reason...";
        if (appendUserPermissionsCSV(username, sharedUsername, privileges)) {
            output = "File Shared";
        } else {
            output = "Issue with File Share, do you write permissions on this file? If not, you cannot share the file.";
        }
        return output;
    }


    public boolean appendUserPermissionsCSV(String username, String sharedUsername, String privileges) throws IOException, CsvException, CsvValidationException {
        CSVWriter writer = new CSVWriter(new FileWriter(this.csv, true));

        // See if already in file 
        int row = this.searchUserPermissionsCSV(username);
        if (row != -1) {
            String[] userPermissionInfo = this.retrieveUserPermissionsCSV(username);
            if (userPermissionInfo != null && userPermissionInfo.length == 3 && userPermissionInfo[2].contains("w")) {
                // then we are looking to append new permissions for username
                if (sharedUsername == null) {
                    // Delete line bc needing to override file on server potentially
                    this.deleteUserPermissions(row);
                } 
                // then we are looking to append new permissions for sharedUsername
                else {
                    // check if the sharedUsername is already in the share file
                    int sharedRow = this.searchUserPermissionsCSV(sharedUsername);
                    if (sharedRow != -1) {
                        String[] sharedUserPermissionInfo = this.retrieveUserPermissionsCSV(username);
                        if (sharedUserPermissionInfo != null && sharedUserPermissionInfo.length == 3) {
                            String currentPermissions = sharedUserPermissionInfo[2];
                            if (privileges.equals(currentPermissions)) {
                                writer.close();
                                return true;
                            } else {
                                this.deleteUserPermissions(sharedRow);
                                privileges = "rw";
                            }
                        }
                    }
                    String [] shareKeyInfo = {this.path, sharedUsername, privileges};
                    writer.writeNext(shareKeyInfo);
                    writer.close();
                    return true;
                }
            }
            // case where user only has read privileges, so shouldn't be able to edit the permissions of the file
            else {
                writer.close();
                return false;
            }
        }
        else {
            ArrayList<Integer> rowList = this.searchFilenameCSV();
            // This is the case where you don't have permission to write to this file name and someone else does
            if (rowList.size() != 0) {
                // userOutput = "You do not have permission to override the current file with that name on the server. Please change the name of your file.";
                // System.out.println(userOutput);
                writer.close();
                return false;
            }
        }
    
        String [] fileKeyInfo = {this.path, username, privileges};
        writer.writeNext(fileKeyInfo);
        writer.close();
        return true;
    }

    public String[] retrieveUserPermissionsCSV(String username) throws IOException, CsvValidationException {
        try {
            FileReader filereader = new FileReader(this.csv); 
        
            CSVReader csvReader = new CSVReader(filereader); 
            String[] nextRecord = {}; 
  
            // we are going to read data line by line 
            while ((nextRecord = csvReader.readNext()) != null) { 
                if (nextRecord.length > 0 && nextRecord[0].equals(this.path) && nextRecord[1].equals(username)) {
                    csvReader.close();
                    return nextRecord;
                }
            }
        }
        catch (IOException io) {
            System.out.println(io);
        }
        // System.out.println("File Access Denied");
        return null;
    }

    public int searchUserPermissionsCSV(String username) throws IOException, CsvValidationException {
        try {
            CSVReader csvReader = new CSVReader(new FileReader(this.csv)); 
            String[] nextRecord = {}; 
            int row = 0;
            // we are going to read data line by line 
            while ((nextRecord = csvReader.readNext()) != null) { 
                if (nextRecord.length > 0 && nextRecord[0].equals(this.path) && nextRecord[1].equals(username)) {
                    csvReader.close();
                    return row;
                }
                row++;
            }
            csvReader.close();
        }
        catch (IOException io) {
            System.out.println(io);
        }
        return -1;
    }

    public int searchUserPermissionsCSV() throws IOException, CsvValidationException {
        try {
            CSVReader csvReader = new CSVReader(new FileReader(this.csv)); 
            String[] nextRecord = {}; 
            int row = 0;
            // we are going to read data line by line 
            while ((nextRecord = csvReader.readNext()) != null) { 
                if (nextRecord.length > 0 && nextRecord[0].equals(this.path)) {
                    csvReader.close();
                    return row;
                }
                row++;
            }
            csvReader.close();
        }
        catch (IOException io) {
            System.out.println(io);
        }
        return -1;
    }

    public ArrayList<Integer> searchFilenameCSV() throws IOException, CsvValidationException {
        ArrayList<Integer> rowList = new ArrayList<Integer>();
        try {
            CSVReader csvReader = new CSVReader(new FileReader(this.csv)); 
            String[] nextRecord = {}; 
            int row = 0;
            // we are going to read data line by line 
            while ((nextRecord = csvReader.readNext()) != null) { 
                if (nextRecord.length > 0 && nextRecord[0].equals(this.path)) {
                    rowList.add(row);
                }
                row++;
            }
            csvReader.close();
        }
        catch (IOException io) {
            System.out.println(io);
        }
        return rowList;
    }

    public void deleteUserPermissions(int rowNumber) throws IOException, CsvException, CsvValidationException {
        CSVReader reader = new CSVReader(new FileReader(this.csv));
        List<String[]> allElements = reader.readAll();
        allElements.remove(rowNumber);
        FileWriter sw = new FileWriter(this.csv);
        CSVWriter writer = new CSVWriter(sw);
        writer.writeAll(allElements);
        reader.close();
        writer.close();
    }

    public void deleteFileCSV(ArrayList<Integer> rowList) throws IOException, CsvException, CsvValidationException {
        CSVReader reader = new CSVReader(new FileReader(this.csv));
        List<String[]> allElements = reader.readAll();
        for (int i = rowList.size() - 1; i >= 0; i--) {
            int row = rowList.get(i);
            allElements.remove(row);
        }
        System.out.println(allElements);
        CSVWriter writer = new CSVWriter(new FileWriter(this.csv));
        writer.writeAll(allElements);
        reader.close();
        writer.close();
    }
}