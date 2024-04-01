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
//  * sends a string to our firebase!!!!
//  *
//  */


// package com.security;

// import com.google.firebase.database.*;
// import utils.FirebaseInit;

// public class App 
// {
//     public static void main( String[] args )
//     {

//         FirebaseInit.initialize();
//         DatabaseReference databaseRef = FirebaseDatabase.getInstance().getReference();
        
//         String data = "This is a test message.";

//         // Set the data in Firebase
//         databaseRef.setValue(data, new DatabaseReference.CompletionListener() {
//             @Override
//             public void onComplete(DatabaseError error, DatabaseReference ref) {
//                 if (error == null) {
//                     System.out.println("Data sent to Firebase.");
//                 } else {
//                     System.err.println("Failed to send Firebase: " + error.getMessage());
//                 }
//             }
//         });
//     }
// }
