package app.utils;

import java.io.*;

public class FileHandler {
    String path;

    public FileHandler (String path) {
        this.path = path;
    }

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
}