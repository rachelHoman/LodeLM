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


The Client will first be prompted to choose a login option: (1) Login, (2) Forgot Password, (3) Create Account, and (4) Exit. 

1. Login: This is for returning users to log on. The user to prompted to enter their username and then respective password. If they match what is stored on the server (hashed and encrypted) then they are allowed on.
2. Forgot Password: This is for returning users to recover their passwords. The user is prompted to enter their username along with their email that they signed up with. If they match was is stored on the server then a one-time passcode(OTP) is sent to their email. If they enter the correct 6-digit code, then they are prompted to enter a new password (twice to ensue correctness and must meet strong password requirements). Then they are logged into the server.
3. Create Account: This is for any user. For users who want to create a new account they are prompted to enter a username (cannot be empty or used), then a password (twice to ensue correctness and must meet strong password requirements), then email. Upon entering an email they are sent an OTP which they will enter and if correct, their account is created and they are let on the server.
4. Exit: This is for any user. If they user does not want to log on then they can simply exit the connection. 


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
    - index.html can be opened to see the results (LodeLMmvn/target/site/jacoco/index.html)
