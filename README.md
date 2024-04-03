# LodeLM
**A large language model collaboration platform**

By Anika Gupta, Rachel Homan, and Christy Marchese

to compile, package, and execute the maven project:

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

The user can send a file to the server

`send <file_name>`

The user can download a file from the server

`download <file_name>`

The user can delete a file on the server

`delete <file_name>`

The user can list the files on the server

`list`

The user can see what directory they are in

`pwd`

test
