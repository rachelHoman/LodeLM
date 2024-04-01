package com.security;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
    }
}

// /**
//  * This is test code of App that 
//  * sends a file to our firebase!!!!
//  *
//  */

// package com.security;

// import com.google.firebase.database.*;
// import utils.FirebaseInit;
// import java.io.*;

// public class App 
// {
//     public static void main( String[] args )
//     {
//         FirebaseInit.initialize();
//         DatabaseReference databaseRef = FirebaseDatabase.getInstance().getReference();

//         String filePath = "server_data/file.txt";
//         String fileContents = readFileContents(filePath);

//         // Generate a unique key for the upload
//         String uploadKey = databaseRef.push().getKey();

//         // Set the file contents in Firebase under the unique key
//         databaseRef.child(uploadKey).setValue(fileContents, new DatabaseReference.CompletionListener() {
//             @Override
//             public void onComplete(DatabaseError error, DatabaseReference ref) {
//                 if (error == null) {
//                     System.out.println("File sent to Firebase with key: " + uploadKey);
//                 } else {
//                     System.err.println("Failed to send Firebase: " + error.getMessage());
//                 }
//             }
//         });
//     }

//     // Method to read file contents
//     private static String readFileContents(String filePath) {
//         StringBuilder contentBuilder = new StringBuilder();
//         try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
//             String line;
//             while ((line = br.readLine()) != null) {
//                 contentBuilder.append(line).append("\n");
//             }
//         } catch (IOException e) {
//             e.printStackTrace();
//         }
//         return contentBuilder.toString();
//     }
// }