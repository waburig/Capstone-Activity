**Final Capstone Activity**
**Challenge 1: SQL Injection**

In this part, you must discover user account information on a server and crack the password of Bob Smith's account. You will then locate the file that contains the Challenge 1 code and use Bob Smith's account credentials to open the file at 192.168.0.10 to view its contents.
Step 1: Preliminary setup
a.	Open a browser and go to the website at 10.5.5.12.
Note: If you have problems reaching the website, remove the https:// prefix from the IP address in the browser address field.
b.	Login with the credentials admin / password.
c.	Set the DVWA security level to low and click Submit.

I opened the website above and setup the security as instructed. On the userid I entered 1 in the user the user ID the results will be as below.

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot1.png

Step 2: Retrieve the user credentials for the Bob Smith's account.
a.	Identify the table that contains usernames and passwords.
b.	Locate a vulnerable input form that will allow you to inject SQL commands.
c.	Retrieve the username and the password hash for Bob Smith's account.
From the instructions above I tried **1' UNION SELECT 1,2 -- -** which gave the below results

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot2.png

On the same I used this command gave the below results: **1' UNION SELECT user, password FROM users -- -**

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot3.png

Step 3: Crack Bob Smith's account password.
Use any password hash cracking tool desired to crack Bob Smith’s password.
To target bob, the following command is used: **1' UNION SELECT user, password FROM users WHERE first_name='Bob' -- -**

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot4.png


I cracked the Bob Smith’s Password Hash as shown below.
hash:5f4dcc3b5aa765d61d8327deb882cf99
**This cracks to:password**

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot5.png

Step 4: Locate and open the file with Challenge 1 code.
a.	Log into 192.168.0.10 as Bob Smith.
b.	Locate and open the flag file in the user's home directory.
c.	What is the message contained in the file? Enter the code that you find in the file.

The results of the above are on the screenshot below. The message contained in the file: 
Congratulations! 
You found flag for challange 1!
The code for this challange is 8748wf8j.

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot6.png

Step 5: Research and propose SQL attack remediation.
1. Use Parameterized Queries / Prepared Statements
This is the most effective defense.
Example (PHP + PDO):
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $id]);
User input is never concatenated into SQL

2. Input Validation & Whitelisting
Only allow expected input.
•	Reject anything that doesn’t match format
•	IDs should be numeric
•	Emails should match email regex

3. Escaping Input (if Parameterization Isn’t Possible)
Use proper escaping for special characters:
PHP MySQLi example:
$id = mysqli_real_escape_string($conn, $_GET['id']);
Not as safe as parameterized queries, but helps prevent basic injection.

4. Web Application Firewall (WAF)
A WAF can detect and block SQLi patterns before reaching the application.
ModSecurity
Cloudflare WAF
FortiWeb on Fortinet platforms

5. Error Handling and Logging
Do not expose SQL errors to users.
Bad (vulnerable):
You have an error in your SQL syntax…
Good (secure):
Invalid request

**Challenge 2: Web Server Vulnerabilities**
In this part, you must find vulnerabilities on an HTTP server. Misconfiguration of a web server can allow for the listing of files contained in directories on the server. You can use any of the tools you learned in earlier labs to perform reconnaissance to find the vulnerable directories.
In this challenge, you will locate the flag file in a vulnerable directory on a web server.
Step 1: Preliminary setup
a.	If not already, log into the server at 10.5.5.12 with the admin / password credentials.
b.	Set the application security level to low.

The website was opened and security set to low

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot7.png

Step 2: From the results of your reconnaissance, determine which directories are viewable using a web browser and URL manipulation.
Perform reconnaissance on the server to find directories where indexing was found.

Reconnaissance done using drib:
Indexed (listable) directories found:
•	http://10.5.5.12/config/
•	http://10.5.5.12/docs/
•	http://10.5.5.12/external/

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot8.png

Step 3: View the files contained in each directory to find the file containing the flag.
Create a URL in the web browser to access the viewable subdirectories. Find the file with the code for Challenge 2 located in one of the subdirectories.

The below two subdirectories can be checked for the files.

DIRECTORY: http://10.5.5.12/config/                                                 
DIRECTORY: http://10.5.5.12/docs/ 

The filename with the Challenge 2 code was **db_form.html.**

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot9.png

The subdirectory which held the file was **/config/ subdirectory** 

What is the message contained in the flag file?
Great work!

You found the flag file for Challenge 2! 

The code for this flag is:  aWe-4975

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot10.png

Step 4: Research and propose directory listing exploit remediation.
Restrict Access to Sensitive Directories
•	Use .htaccess or server configuration to limit access:
Require all denied
Remove Unnecessary Files
•	Delete backup files, old configuration files, and unused documentation from the web root.
Disable Directory Indexing
•	On Apache, remove or disable the Indexes option:
•	Options -Indexes
•	This prevents users from viewing directory contents.

**Challenge 3: Exploit open SMB Server Shares**
In this part, you want to discover if there are any unsecured shared directories located on an SMB server in the 10.5.5.0/24 network. You can use any of the tools you learned in earlier labs to find the drive shares available on the servers.
Step 1: Scan for potential targets running SMB.
I have used nmap scan tool to scan the 10.5.5.0/24 LAN for potential targets for SMB enumeration.

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot11.png

The host gravemind.pc (10.5.5.14) has SMB-related ports 139 and 445 open, indicating it is running SMB services. 

Step 2: Determine which SMB directories are shared and can be accessed by anonymous users.
Use a tool to scan the device that is running SMB and locate the shares that can be accessed by anonymous users.

The SMB server lists the shares homes, workfiles, print$, and IPC$. All of these shares are accessible using anonymous authentication, 
indicating that the SMB server allows unauthenticated access refer to the above screenshot.

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot12.png

Step 3: Investigate each shared directory to find the file.
Use the SMB-native client to access the drive shares on the SMB server. Use the dir, ls, cd, and other commands to find subdirectories and files.
Locate the file with the Challenge 3 code. Download the file and open it locally.
The file is found in the print$ SMB share, and the name of the file with the challenge 3 code is sxij42.txt.
The code for this challenge is NWs39691.

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot13.png

Here are two clear and correct remediation methods you can submit for SMB attack prevention:
SMB Attack Remediation Methods
1.	Disable Anonymous (Guest) Access
	•	Configure the SMB server to require authentication for all shares.
	•	Remove or restrict guest access so that only authorized users can connect.
	•	This prevents unauthenticated users from listing or accessing shared directories.
2.	Restrict SMB Access Using Network Controls
	•	Use a firewall to block SMB ports (TCP 139 and 445) from untrusted networks.
	•	Limit SMB access to specific IP addresses or internal networks only.
	•	This reduces exposure to network-based SMB attacks.

Challenge 4: Analyze a PCAP File to Find Information.
As part of your reconnaissance effort, your team captured traffic using Wireshark. The capture file, SA.pcap, is located in the Downloads subdirectory within the kali user home directory.
Step 1: Find and analyze the SA.pcap file.
Analyze the content of the PCAP file to determine the IP address of the target computer and the URL location of the file with the Challenge 4 code.
**The Ip address of the target computer is 10.5.5.11. The PCAP below shows repeated HTTP requests from 10.5.5.1 to 10.5.5.11**

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot14.png

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot15.png

From the HTTP GET requests visible in the PCAP, the following directories on the target computer (10.5.5.11) are revealed:
	•	/styles/
	•	/test/
	•	/data/
	•	/webservices/
	•	/webservices/rest/
	•	/webservices/soap/
	•	/webservices/soap/lib/
	•	/includes/
	•	/passwords/
	•	/javascript/
	•	/icons/
	
Step 2: Use a web browser to display the contents of the directories on the target computer.

Use a web browser to investigate the URLs listed in the Wireshark output. Find the file with the code for Challenge 4.
**The URL of the file is: http://10.5.5.11/data/user_accounts.xml. This XML file contains the entry labeled Flag, which reveals the Challenge 4 code.**

https://github.com/waburig/Capstone-Activity/blob/main/Screenshots4/Screenshot16.png

The content of the above file is:
<Employees>
<Employee ID="0">
<UserName>Flag</UserName>
<Password>Here is the Code for Challenge 4!</Password>
<Signature>21z-1478K</Signature>
<Type>Flag</Type>
</Employee>
<Employee ID="1">
<UserName>admin</UserName>
<Password>adminpass</Password>
<Signature>g0t r00t?</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="2">
<UserName>adrian</UserName>
<Password>somepassword</Password>
<Signature>Zombie Films Rock!</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="3">
<UserName>john</UserName>
<Password>monkey</Password>
<Signature>I like the smell of confunk</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="4">
<UserName>jeremy</UserName>
<Password>password</Password>
<Signature>d1373 1337 speak</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="5">
<UserName>bryce</UserName>
<Password>password</Password>
<Signature>I Love SANS</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="6">
<UserName>samurai</UserName>
<Password>samurai</Password>
<Signature>Carving fools</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="7">
<UserName>jim</UserName>
<Password>password</Password>
<Signature>Rome is burning</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="8">
<UserName>bobby</UserName>
<Password>password</Password>
<Signature>Hank is my dad</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="9">
<UserName>simba</UserName>
<Password>password</Password>
<Signature>I am a super-cat</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="10">
<UserName>dreveil</UserName>
<Password>password</Password>
<Signature>Preparation H</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="11">
<UserName>scotty</UserName>
<Password>password</Password>
<Signature>Scotty do</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="12">
<UserName>cal</UserName>
<Password>password</Password>
<Signature>C-A-T-S Cats Cats Cats</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="13">
<UserName>john</UserName>
<Password>password</Password>
<Signature>Do the Duggie!</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="14">
<UserName>kevin</UserName>
<Password>42</Password>
<Signature>Doug Adams rocks</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="15">
<UserName>dave</UserName>
<Password>set</Password>
<Signature>Bet on S.E.T. FTW</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="16">
<UserName>patches</UserName>
<Password>tortoise</Password>
<Signature>meow</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="17">
<UserName>rocky</UserName>
<Password>stripes</Password>
<Signature>treats?</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="18">
<UserName>tim</UserName>
<Password>lanmaster53</Password>
<Signature>Because reconnaissance is hard to spell</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="19">
<UserName>ABaker</UserName>
<Password>SoSecret</Password>
<Signature>Muffin tops only</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="20">
<UserName>PPan</UserName>
<Password>NotTelling</Password>
<Signature>Where is Tinker?</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="21">
<UserName>CHook</UserName>
<Password>JollyRoger</Password>
<Signature>Gator-hater</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="22">
<UserName>james</UserName>
<Password>i<3devs</Password>
<Signature>Occupation: Researcher</Signature>
<Type>Admin</Type>
</Employee>
<Employee ID="23">
<UserName>ed</UserName>
<Password>pentest</Password>
<Signature>Commandline KungFu anyone?</Signature>
<Type>Admin</Type>
</Employee>
</Employees>


**The code of the challenge is: 21z-1478K (see below extraction from above)**

<Employees>
<Employee ID="0">
<UserName>Flag</UserName>
<Password>Here is the Code for Challenge 4!</Password>
<Signature>21z-1478K</Signature>
<Type>Flag</Type>
</Employee>

Step 3: Research and propose remediation that would prevent file content from being transmitted in clear text.

Two remediation methods are:
1.	Implement HTTPS (TLS/SSL) to encrypt data in transit and prevent clear text transmission.
2.	Apply proper access controls by restricting directory access and disabling directory listing for sensitive files.







