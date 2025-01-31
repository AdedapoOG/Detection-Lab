1# Detection-Lab

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned


- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Network analysis tools (such as Wireshark) for capturing and examining network traffic.
- Telemetry generation tools to create realistic network traffic and attack scenarios.

## Steps
# Network_Configuration
    
- The following screenshot shows the **Network Adapter settings** for both **Kali Linux** and **Metasploitable 2** virtual machines, which are set to **Host-Only** networking for communication.

  ![Kali_adapter_settings](https://github.com/user-attachments/assets/7b6403dd-1a7f-453f-8878-d22fa3e262ae)

  ![metasploit_adapter_settings](https://github.com/user-attachments/assets/30010a20-84b3-4cfd-9938-e7bbfef445db)

# IP_Configuration
screenshot of the Kali Linux terminal running ifconfig, showing the IP address of Kali Linux. This verifies that Kali Linux has an IP on the correct subnet 
![image](https://github.com/user-attachments/assets/565b8993-156d-4a27-8a55-c598cd836efb)
screenshot of the Metasploitable 2 terminal running ifconfig, showing the IP address of Metasploitable 2. This verifies that Metasploitable 2 has an IP on the correct subnet and confirms the VM’s network configuration.
![If_config_matasploit](https://github.com/user-attachments/assets/cd71d685-18c4-4993-b510-85c12edb0210)
# Ping_Test
 Screenshot capturing the terminal in Kali Linux showing a successful ping to Metasploitable 2. This demonstrates that the VMs are able to communicate with each other.
 ![image](https://github.com/user-attachments/assets/c096602b-e5dd-4e29-bf55-44f26842f21d)
 
# Nmap_Scan_Command/
After configuring the network, I ran an Nmap scan on Metasploitable 2 to check for open ports and services.

Here are the results of the scan:
![image](https://github.com/user-attachments/assets/83e4f6eb-9b50-4ef6-8f60-0e4f637548a9)

![image](https://github.com/user-attachments/assets/30f00b37-a71e-4027-9e45-62b1c9ed37ba)

Vulnerability Analysis of Open Ports
After running the Nmap scan, the following ports were identified as open on **Metasploitable 2**:
### 1. Port 21 - FTP
**Vulnerability**
Port 21 is running vsftpd 2.3.4, an outdated FTP service.
Anonymous login is enabled, allowing anyone to access the server without credentials.

Objective is to verify the extent of access through anonymous login and
Check for the known backdoor vulnerability in vsftpd 2.3.4.
![image](https://github.com/user-attachments/assets/4630ae49-f57d-4481-a50e-e73abfcebc49)
No files were found during the ls command.
Even if the directory is empty. Unauthorized users can still upload or manipulate files (if permissions allow), making the server vulnerable.

**Recommendation**
Disable Anonymous Login: Restrict access to authenticated users only by updating the FTP configuration file.
Upgrade vsftpd: Update to the latest version of vsftpd to mitigate known vulnerabilities.
Secure FTP Traffic: Use FTPS (FTP Secure) or SFTP (Secure FTP over SSH) instead of plain FTP to encrypt traffic and credentials.
Monitor FTP Activity: Implement logging and monitoring to detect unauthorized access attempts.

### 2. Port 22 - SSH
**Vulnerability**: Weak passwords can lead to brute-force attacks.

objective is to test by trying to log in using default credentials
![image](https://github.com/user-attachments/assets/91a99c83-f317-48d8-be67-7f31ae934b2c)
I was able to succesfully log in to the machine via SSH using the default credentials
this can be exploited as attackers can log in and gain remote shell access

**Recommendation**
Use public-key authentication and disable password-based logins.
update OpenSSH to the latest version

### 3. Port 23 - Telnet
**Vulnerability**: Transmits data in plaintext, including passwords.

objective is to determine if Telnet allows unauthorized assess and test for plaintext crednetial transmission
![image](https://github.com/user-attachments/assets/a542b22c-bb6b-4180-b548-12dbfd98451a)
Telnet is inherently insecure as credentials and data are transmitted in plaintext, making it easy to intercept with tools like Wireshark.
also, using default credentials (e.g., msfadmin) is a critical weakness.


**Recommendation**
Disable Telnet and use SSH.

### 4. Port 25 - SMTP
**Vulnerability**
Commands like VRFY and EXPN allow attackers to identify valid users on the system.
Open Relay: If the server allows emails to be sent without authentication, it can be used for spamming or phishing.

objective is determine if the Postfix SMTP server is misconfigured or vulnerable and test for email-related vulnerabilities, such as user enumeration or open relay.

Test Result
![image](https://github.com/user-attachments/assets/c0166af8-79e5-44a4-9656-a83002d3ad0e)

1. VRFY Command
Output: 252 2.0.0 root
The VRFY command successfully verified the existence of the root user. This indicates that user enumeration is possible, which is a significant vulnerability.
2. EXPN Command
Output: 502 5.5.2 Error: command not recognized
The EXPN command is disabled on the server, which is a positive security measure. No vulnerability here.
3. Open Relay Test
Output:
250 2.1.0 Ok for the sender address (MAIL FROM).
554 5.7.1 Relay access denied for the recipient address (RCPT TO).
The SMTP server is not an open relay, which is good. It only allows email relaying from authorized users or internal domains.

vulnerability found
Attackers can use the VRFY command to verify the existence of valid system users (e.g., root, admin).
This information can aid in brute-force or phishing attacks.




**Recommendation**
Update the Postfix SMTP configuration (/etc/postfix/main.cf) to disable VRFY
Configure the SMTP server to require authentication for sending emails, even for internal users.
To use the latest version of Postfix to address potential security flaws in older versions.
To Enable detailed logging to monitor suspicious SMTP activity and identify potential enumeration attempts.

### 5. Port 80 - HTTP
**Vulnerability**
Outdated Apache versions may contain vulnerabilities like buffer overflows or directory traversal.
Web applications may be vulnerable to SQL injection or XSS.

objective is to access the web server in a browser and scan for vulnerabilities

**Recommendation**
Update Apache to the latest version.
Secure web applications by sanitizing inputs.









