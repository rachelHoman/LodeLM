// package utils;

// import com.google.firebase.database.*;
// import java.util.Base64;
// import java.io.*;

// public class DatabHandler {
//     private DatabaseReference databaseRef;

//     public DatabHandler() {
//         // Initialize Firebase
//         FirebaseInit.initialize();
//         // Get a reference to the Firebase Realtime Database
//         this.databaseRef = FirebaseDatabase.getInstance().getReference();
//     }

//     public void uploadFile(String filePath, String fileName) {
//         try {
//             // Read the contents of the file
//             File file = new File(filePath);
//             FileInputStream fileInputStream = new FileInputStream(file);
//             byte[] fileBytes = new byte[(int) file.length()];
//             fileInputStream.read(fileBytes);
//             fileInputStream.close();
    
//             // Convert file bytes to Base64 string
//             String fileBase64 = Base64.getEncoder().encodeToString(fileBytes);
    
//             // Modify file name to remove invalid characters
//             String sanitizedFileName = sanitizeFileName(fileName);
    
//             // Upload file to Firebase Realtime Database
//             databaseRef.child("files").child(sanitizedFileName).setValue(fileBase64, new DatabaseReference.CompletionListener() {
//                 @Override
//                 public void onComplete(DatabaseError error, DatabaseReference ref) {
//                     if (error == null) {
//                         System.out.println("File uploaded to Firebase with name: " + sanitizedFileName);
//                     } else {
//                         System.err.println("Failed to upload file to Firebase: " + error.getMessage());
//                     }
//                 }
//             });
//         } catch (IOException e) {
//             e.printStackTrace();
//         }
//     }
    
//     private String sanitizeFileName(String fileName) {
//         // Replace invalid characters with valid ones
//         return fileName.replaceAll("[.#$\\[\\]]", "_");
//     }
    
// }

package utils;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.database.*;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;

public class DatabHandler {
    private static DatabaseReference databaseRef;

    // Initialize Firebase only once
    static {
        initializeFirebase();
    }

    private static void initializeFirebase() {
        try {
            FileInputStream serviceAccount = new FileInputStream("/Users/Aniku/Downloads/serviceAccountKey.json");

            FirebaseOptions options = new FirebaseOptions.Builder()
                    .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                    .setDatabaseUrl("https://lodelm-936f0-default-rtdb.firebaseio.com/")
                    .build();

            FirebaseApp.initializeApp(options);
            databaseRef = FirebaseDatabase.getInstance().getReference();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void sendFile(String filePath, String fileName) {
        String fileContents = readFileContents(filePath);

        // Generate a unique key for the upload
        String uploadKey = databaseRef.push().getKey();

        // Set the file contents in Firebase under the unique key
        databaseRef.child(uploadKey).setValue(fileContents, new DatabaseReference.CompletionListener() {
            @Override
            public void onComplete(DatabaseError error, DatabaseReference ref) {
                if (error == null) {
                    System.out.println("File sent to Firebase with key: " + uploadKey);
                } else {
                    System.err.println("Failed to send Firebase: " + error.getMessage());
                }
            }
        });
    }

    // public static void createUser(String usernm, String emailid, String pwdstr) {
    //     try {
    //         // Create the user with email and password
    //         UserRecord.CreateRequest request = new UserRecord.CreateRequest()
    //         .setDisplayName(usernm)
    //         .setEmail(emailid)
    //         .setPassword(pwdstr)
    //         // Add other user data as custom claims, profile information, etc.
    //         // For example, you can add custom claims or additional profile data
    //         .setEmailVerified(false); // Set email verification status
    //         UserRecord userRecord = FirebaseAuth.getInstance().createUser(request);
            
    //         // Successfully created user
    //         System.out.println("Successfully created user: " + userRecord.getUid());
    //     } catch (Exception e) {
    //         // Handle any errors
    //         System.err.println("Error creating user: " + e.getMessage());
    //     }
    // }

    // public static void sendUser(String usrn, String pwds) {
    //         databaseRef.child("userInfo").setValue("userInfoData", new DatabaseReference.CompletionListener() {
    //             @Override
    //             public void onComplete(DatabaseError error, DatabaseReference ref) {
    //                 if (error == null) {
    //                     System.out.println("User info data written to database successfully.");
    //                 } else {
    //                     System.err.println("Failed to write user info data to database: " + error.getMessage());
    //                 }
    //             }
    //         });
    // }

    public static void createUser(String usernm, String emailid, String pwdstr) {
        try {
            // Create the user with email and password
            UserRecord.CreateRequest request = new UserRecord.CreateRequest()
                    .setDisplayName(usernm)
                    .setEmail(emailid)
                    .setPassword(pwdstr);
                    // You can add additional properties here if needed
                    // .setDisabled(false); // Set to true if you want to disable the user
    
            UserRecord userRecord = FirebaseAuth.getInstance().createUser(request);
    
            // Successfully created user
            System.out.println("Successfully created user: " + userRecord.getUid());
        } catch (Exception e) {
            // Handle any errors
            System.err.println("Error creating user: " + e.getMessage());
        }
    }


    private static void storeUserInfo(String userId, String username, String email) {
        // Get a reference to the Firebase Realtime Database
        FirebaseDatabase database = FirebaseDatabase.getInstance();
        DatabaseReference usersRef = database.getReference("users");

        // Create a new child node under "users" with the user's UID
        DatabaseReference userRef = usersRef.child(userId);

        // Set user information as key-value pairs
        userRef.child("username").setValue(username);
        userRef.child("email").setValue(email);

        System.out.println("User information stored successfully.");
    }
    

    // Method to read file contents
    private static String readFileContents(String filePath) {
        StringBuilder contentBuilder = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                contentBuilder.append(line).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return contentBuilder.toString();
    }
}
