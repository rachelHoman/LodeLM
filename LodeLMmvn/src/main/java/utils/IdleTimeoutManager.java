package utils;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import activities.Client;
import activities.ClientHandler;

import java.time.Instant;

public class IdleTimeoutManager {
    private static final long IDLE_TIMEOUT = 5 * 60 * 1000; // 5 minutes in milliseconds
    private static Map<String, Instant> lastActivityMap; 
    private FileHandler fileHandler; 

    public IdleTimeoutManager(Map<String, Instant> lastActivityMap, FileHandler fileHandler) {
        IdleTimeoutManager.lastActivityMap = lastActivityMap != null ? lastActivityMap : new HashMap<>();
        this.fileHandler = fileHandler;
    }

    public void startIdleTimeoutCheck() {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                checkIdleUsers();
            }
        }, 0, IDLE_TIMEOUT); // Check for idle users periodically
    }

    private void checkIdleUsers() {
        Instant now = Instant.now();
        for (Map.Entry<String, Instant> entry : lastActivityMap.entrySet()) {
            String user = entry.getKey();
            Instant lastActivityTime = entry.getValue();
            long idleTime = now.toEpochMilli() - lastActivityTime.toEpochMilli();
            if (idleTime >= IDLE_TIMEOUT) {
                // User has been idle for more than 5 minutes, logout the user
                logoutUser(user);
            }
        }
    }

    private void logoutUser(String user) {
        // Perform logout operation for the user
        System.out.println("Logging out user: " + user);
        FileHandler.logAuditAction(user, "admin", "Logout due to inactivity", "audit_log.txt");
        
        Client.logoutUser(clientSocket, dataInputStream, dataOutputStream, userInput);
    }

    // Method to update the last activity time for a user
    public static void updateUserActivity(String user) {
        lastActivityMap.put(user, Instant.now());
    }
}