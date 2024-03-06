import java.io.*;
import java.net.*;
import java.util.List;
import java.util.ArrayList;

public class ClientHandler implements Runnable {
    private Socket clientSocket;
    private PrintWriter out;
    private BufferedReader in;
    private String username;

    public ClientHandler(Socket socket) {
        this.clientSocket = socket;
    }

    public void run() {
        try {
            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

            // Receive username from client
            this.username = in.readLine();
            System.out.println("Received username: " + this.username);

            // Initialize project list for the user
            // TODO: connect username to user database object and pull in associated user projects from there, not the server class
            List<String> userProjects = Server.getUserProjects().computeIfAbsent(username, k -> new ArrayList<>());

            // Send greeting message to client
            out.println("Hi " + this.username);

            // Handle client requests
            // TODO: give the users a list of things they can do on the server to prompt them
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                System.out.println("Received from client: " + inputLine);

                // Handle create project command
                if (inputLine.startsWith("create ")) {
                    String projectName = inputLine.substring(7); // Extract project name
                    if (createProject(projectName, userProjects)) {
                        out.println("Project '" + projectName + "' created successfully.");
                    } else {
                        out.println("Failed to create project '" + projectName + "'.");
                    }
                } 
                // Handle list projects command
                else if (inputLine.equals("list projects")) {
                    out.println("Your projects: " + userProjects.toString());
                }
                else {
                    // Example of responding to client
                    //out.println("Server received: " + inputLine);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                // Close connections
                in.close();
                out.close();
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private boolean createProject(String projectName, List<String> userProjects) {
        try {
            // TODO: make this a projects object not directory bc we don't want to save this on our local devices
            // Create the "projects" directory if it doesn't exist 
            File projectsDir = new File(Server.PROJECTS_DIRECTORY);
            if (!projectsDir.exists()) {
                projectsDir.mkdirs(); // mkdirs() will create parent directories if necessary
            }

            // Create a new empty text file for the project
            File projectFile = new File(Server.PROJECTS_DIRECTORY + projectName + ".txt");
            if (projectFile.createNewFile()) {
                // Add project to user's project list
                userProjects.add(projectName);
                return true;
            } else {
                return false;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
