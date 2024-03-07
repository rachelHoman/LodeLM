package app.utils;

import java.io.*;

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
    public void sendFile(DataOutputStream dataOutputStream) throws FileNotFoundException, IOException {
        int bytes = 0;
        File file = new File(this.path);
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

    /***
     * Receives file via the given input stream and writes it to the output stream
     * 
     * DataInputStream dataInputStream: the input stream to read in the file through
     * 
     * return: none
     */
    public void receiveFile(DataInputStream dataInputStream) throws FileNotFoundException, IOException {
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
}