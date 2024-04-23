# LodeLM
**A large language model collaboration platform**

By Anika Gupta, Rachel Homan, and Christy Marchese

Download maven.

Navigate into this folder to run:
    - cd LodeLMmvn

To use it to compile, package, and execute the maven project:

- mvn compile: compiles the main Java source code located in the src/
- mvn test-compile: compiles the test Java source code located in the src/test/
- mvn package: compiles the main source code and packages it into a JAR (Java Archive) file

java -jar target/LodeLMmvn-1.0-SNAPSHOT.jar

to override the main class: 
- runs Server.java: mvn exec:java -Dexec.mainClass="activities.Server"
- runs Client.java: mvn exec:java -Dexec.mainClass="activities.Client"

To run the servers and code first compile the java classes:

`javac Client.java`

or with new file system: `javac ./app/activities/Client.java`

`javac ClientHandler.java`

or with new file system: `javac ./app/activities/ClientHandler.java`

`javac Server.java`

or with new file system: `javac ./app/activities/Server.java`


Then start up the Server.java with:

`java Server.java`

or with new file system: `java app/activities/Server`

Then start the Client:

`java Client.java`

or with new file system: `java app/activities/Client`


The Client will first be prompted to enter a username. After the user puts in their uid the Server recieves that, and tells the Client hi.


;; The user can then create a project file with

;; `create <project_file_name>`

;; The user can view their projects by typing

;; `list projects`

The user can send a file to the server (NOTE: Users are not able to override files on the server by sending a file of the same name unless they have write privileges to the file on the server they are trying to override)

`send <file_name>`

The user can download a file from the server (NOTE: Users are only able to download files that they have read privileges to)

`download <file_name>`

The user can share files to other users on the server (NOTE: Users are only able to share files that they have write access to)

`share <permission> <share_username> <file_name>`
where:
    permission: permission to enable for share_user, either 'r', 'w', or 'rw'
    share_username: username of user to share file with
    file_name: name of file to share

The user can delete a file on the server (NOTE: Users are only able to delete files that they have write privileges to)

`delete <file_name>`

The user can list the files on the server

`list <folder_name>`

The user can see what directory they are in

`pwd`

The user can exit their session

`exit`


Command to run coverage testing analysis:
    - mvn jacoco:prepare-agent test install jacoco:report
    - index.html can be opened to see the results