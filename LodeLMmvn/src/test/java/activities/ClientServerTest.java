package activities;
import junit.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertFalse;

import java.io.*;
import java.net.*;

import org.junit.Before;
import org.junit.Test;

import activities.Client;
import activities.Server;

public class ClientServerTest {
    private Server server;
    private Client client;

    @Test
public void testAuthenticationWithCorrectCredentials() {
    // Simulate client sending correct username and password to the server
    // For simplicity, assume a mock client is used for testing
    try {
        Socket clientSocket = new Socket("localhost", 12345); // Assuming server is running on localhost and port 12345
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        // Send username and password
        out.println("alice"); // Assuming “alice” is a valid username
        out.println("password123"); // Assuming “password123” is the corresponding password
        // Receive authentication response from the server
        String response = in.readLine();
        // Verify that the server authenticates the user successfully
        assertEquals("Authentication successful. Proceeding with connection...", response);
        // Close the client socket
        clientSocket.close();
    } catch (IOException e) {
        e.printStackTrace();
        fail("Connection failed: " + e.getMessage());
    }
}
}
    // @Before
    // public void setUp() {
    //     // Initialize the server
    //     server = new Server();
    //     // Start the server in a separate thread
    //     Thread serverThread = new Thread(() -> Server.main(null));
    //     serverThread.start();
    //     // Allow some time for the server to start
    //     try {
    //         Thread.sleep(1000);
    //     } catch (InterruptedException e) {
    //         e.printStackTrace();
    //     }
    //     // Initialize the client
    //     client = new Client();
    // }

    // @Test
    // public void testAuthenticationSuccess() {
    //     // Test authentication with correct username and password
    //     assertTrue(client.authenticate("alice", "password123"));
    // }

    // @Test
    // public void testAuthenticationFailure() {
    //     // Test authentication with incorrect username and password
    //     assertFalse(client.authenticate("alice", "wrongpassword"));
    // }

    // @Test
    // public void testCreateProject() {
    //     // Test creating a project
    //     assertTrue(client.createProject("new_project"));
    // }

    // @Test
    // public void testListProjects() {
    //     // Test listing projects
    //     String projects = client.listProjects();
    //     assertEquals("project1\nproject2\n", projects); // Assuming project1 and project2 are existing projects
    // }

    // @Test
    // public void testSendFile() {
    //     // Test sending a file
    //     assertTrue(client.sendFile("test.txt"));
    // }

    // @Test
    // public void testDownloadFile() {
    //     // Test downloading a file
    //     assertTrue(client.downloadFile("test.txt"));
    // }

    // @Test
    // public void testDeleteFile() {
    //     // Test deleting a file
    //     assertTrue(client.deleteFile("test.txt"));
    // }
