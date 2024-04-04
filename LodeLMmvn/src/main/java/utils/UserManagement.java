package utils;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;

public class UserManagement {

    public static void createUser(String username, String email, String password) {
        try {
            // Create the user with email and password
            FirebaseAuth auth = FirebaseAuth.getInstance();
            auth.createUser(null)
            auth.createUserWithEmailAndPassword(email, password)
                    .addOnCompleteListener(task -> {
                        if (task.isSuccessful()) {
                            // User creation succeeded, get the user's UID
                            String uid = task.getResult().getUser().getUid();
                            
                            // Store user information in the Realtime Database
                            storeUserInfo(uid, username, email);
                            
                            System.out.println("Successfully created user with UID: " + uid);
                        } else {
                            // User creation failed
                            System.err.println("Error creating user: " + task.getException().getMessage());
                        }
                    });
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

    public static void main(String[] args) {
        // Example usage
        createUser("username", "user@example.com", "password");
    }
}
