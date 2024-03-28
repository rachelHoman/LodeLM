package LodeLMmvn.src.main.java.activities;
import org.junit.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

import org.junit.Before;
import org.junit.Test;

public class ClientServerTest {
    private Server server;
    private Client client;

    @Before
    public void setUp() {
        // Initialize the server
        server = new Server();
        // Start the server in a separate thread
        Thread serverThread = new Thread(() -> Server.main(null));
        serverThread.start();
        // Allow some time for the server to start
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // Initialize the client
        client = new Client();
    }

    @Test
    public void testAuthenticationSuccess() {
        // Test authentication with correct username and password
        assertTrue(client.authenticate("alice", "password123"));
    }

    @Test
    public void testAuthenticationFailure() {
        // Test authentication with incorrect username and password
        assertFalse(client.authenticate("alice", "wrongpassword"));
    }

    @Test
    public void testCreateProject() {
        // Test creating a project
        assertTrue(client.createProject("new_project"));
    }

    @Test
    public void testListProjects() {
        // Test listing projects
        String projects = client.listProjects();
        assertEquals("project1\nproject2\n", projects); // Assuming project1 and project2 are existing projects
    }

    @Test
    public void testSendFile() {
        // Test sending a file
        assertTrue(client.sendFile("test.txt"));
    }

    @Test
    public void testDownloadFile() {
        // Test downloading a file
        assertTrue(client.downloadFile("test.txt"));
    }

    @Test
    public void testDeleteFile() {
        // Test deleting a file
        assertTrue(client.deleteFile("test.txt"));
    }
}
