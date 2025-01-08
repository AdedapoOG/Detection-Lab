# Detection-Lab

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
- **Vulnerability**: Weak passwords can lead to brute-force attacks.
- **Recommendation**: Use public-key authentication and disable password-based logins.

### 3. Port 23 - Telnet
- **Vulnerability**: Transmits data in plaintext, including passwords.
- **Recommendation**: Disable Telnet and use SSH.





