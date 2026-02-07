



WAZUH
SIEM TOOL


<img width="741" height="118" alt="image" src="https://github.com/user-attachments/assets/d88c8ec7-158d-498b-8873-b457d34c9fe4" />












INTRODUCTION
 
Wazuh is an open-source Security Information and Event Management (SIEM) platform designed to provide organizations with comprehensive visibility and security monitoring across their IT infrastructure. It offers features such as log data analysis, intrusion detection, vulnerability assessment, file integrity monitoring, and active response — all integrated within a centralized management and visualization system.
As a next-generation SIEM, Wazuh collects and analyzes data from endpoints, servers, network devices, and cloud environments. It identifies anomalies, correlates events, and generates alerts for potential security incidents. This helps system administrators and security analysts to detect threats early, respond quickly, and maintain continuous situational awareness of their systems.
Wazuh integrates seamlessly with Elastic Stack (Elasticsearch and Kibana) or OpenSearch Dashboard, providing powerful search, visualization, and reporting capabilities. Through dashboards and prebuilt visualization templates, users can view system health, monitor alerts in real time, and investigate security events efficiently.
The Wazuh architecture is built around three core components:
1.	Wazuh Agent – Installed on monitored endpoints to collect system logs, monitor file integrity, detect intrusions, and execute active responses.
2.	Wazuh Manager – A central analysis engine that processes the collected data, applies decoders and rules to detect threats, and generates alerts.
3.	Wazuh Dashboard – A web-based graphical interface for managing agents, viewing alerts, visualizing data, and performing security analysis.
Wazuh also supports integration with external threat intelligence feeds, cloud services, and compliance frameworks such as PCI-DSS, GDPR, and HIPAA, helping organizations maintain regulatory compliance while strengthening their overall security posture.
In summary, Wazuh is a robust, scalable, and flexible security solution suitable for both enterprise and academic environments. Its open-source nature, combined with strong community and vendor support, makes it an ideal choice for implementing a full-featured SIEM for threat detection, log management, and compliance monitoring.

WAZUH SECURITY CAPABILITIES OVERVIEW

Wazuh provides a wide range of security capabilities designed to protect systems, detect threats, and support incident response. Its open-source architecture makes it suitable for both small environments and large enterprise deployments.
1. Threat Detection & Monitoring
Wazuh continuously monitors endpoints and networks for suspicious activity, unauthorized access, malware behavior, and policy violations.
2. Log Collection & Analysis
It collects logs from Windows, Linux, macOS, network devices, and cloud services. These logs are normalized, indexed, and analyzed for security events.
3. File Integrity Monitoring (FIM)
Wazuh detects changes to critical files, system directories, registry keys, and configurations. This helps identify tampering or unauthorized modifications.
4. Intrusion Detection (HIDS)
Using host-based intrusion detection, Wazuh identifies ransomware behavior, privilege escalation attempts, brute-force attacks, and rootkits.
5. Security Configuration Assessment (SCA)
Wazuh checks endpoints for compliance with CIS benchmarks, PCI-DSS, HIPAA, GDPR, and internal security policies.
6. Vulnerability Detection
It scans systems to identify missing patches, outdated software, misconfigurations, and known vulnerabilities across operating systems.
7. Active Response
Wazuh can take automated actions such as blocking malicious IPs, stopping suspicious processes, or isolating compromised endpoints during an attack.
8. Cloud Security Monitoring
Integrated support for AWS, Azure, GCP, and Docker provides visibility into cloud activity, audit logs, and container behavior.

9. Centralized Dashboard & Reporting
The Wazuh dashboard allows SOC teams to visualize alerts, view system health, analyze logs, and generate security reports.

WAZUH IMPLEMENTATION WORKFLOW

SYSTEM REQUIREMENTS
To successfully deploy and operate Wazuh as a Security Information and Event Management (SIEM) tool, certain system and environment prerequisites are required. The setup in this project includes two main components:
•	Wazuh Manager installed on Kali Linux (or equivalent Linux distribution)
•	Wazuh Agent installed on Parrot OS Linux endpoint (or Windows, macOS)
Below are the detailed hardware, software, and network requirements for both components.
________________________________________
1. Hardware Requirements
Component	Minimum	Recommended
CPU	2 cores	4+ cores for better performance
RAM	4 GB	8–16 GB (for medium to large environments)
Storage	50 GB free space	100 GB+ depending on log retention
Network	1 Gbps NIC	Stable high-speed connectivity between manager and agents
2. Software Requirements
For Kali Linux (Wazuh Manager):
•	Operating System: Kali Linux 2024.x or later (Debian-based)
•	Python 3.8+ (preinstalled in most Kali versions)
•	Packages: curl, wget, gnupg, apt-transport-https, unzip
•	Optional Components:
o	OpenSearch / Elasticsearch for indexing and searching events
o	Wazuh Dashboard or Kibana for visualization
•	Root or sudo privileges for installation and service management

Wazuh Agent:
•	Debian 10, 11, 12
•	Ubuntu 18.04, 20.04, 22.04
•	Since Parrot OS is Debian-based, it works, but you must avoid mixing incompatible packages.

Resource	Minimum	Recommended
CPU	1 core	2 cores
RAM	512 MB	1–2 GB
Disk Space	200 MB	500 MB
Network	Must reach Wazuh Manager on port 1514 (TCP/UDP) and 1515	
3. Environment Requirements
•	Stable internet access for downloading Wazuh packages and updates
•	Administrative access to both Kali Linux
•	Synchronization of system time using NTP (important for log correlation and alert timestamps)
•	Optional: A virtualized lab environment (VirtualBox, VMware, or Hyper-V) for testing and isolation


WAZUH MANAGER INSTALLATION

Installing Wazuh
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
 <img width="900" height="574" alt="image" src="https://github.com/user-attachments/assets/54c3b3cc-c818-48e6-a05e-36d97930d058" />

Once the assistant finishes the installation, the output shows the access credentials and a message that confirms that the installation was successful.
INFO: --- Summary ---
INFO: You can access the web interface https://<WAZUH_DASHBOARD_IP_ADDRESS>
    User: admin
    Password: <ADMIN_PASSWORD>
    <img width="900" height="266" alt="image" src="https://github.com/user-attachments/assets/e58b939c-2552-4a0b-b5c5-ee9820b21ec9" />

INFO: Installation finished.
You now have installed and configured Wazuh.

1.	Access the Wazuh web interface with https://<WAZUH_DASHBOARD_IP_ADDRESS> and your credentials:
o	Username: admin
o	Password: <ADMIN_PASSWORD>
o	 
You can then access the Wazuh Dashboard in your browser:
 <img width="584" height="391" alt="image" src="https://github.com/user-attachments/assets/f7c96a11-0d46-4bd0-840b-763c10818510" />

Note
You can find the passwords for all the Wazuh indexer and Wazuh API users in the wazuh-passwords.txt file inside wazuh-install-files.tar. To print them, run the following command:
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt




WAZUH AGENT INSTALLATION
The Wazuh agent is a multi-platform component of the Wazuh solution and runs on the endpoints you want to monitor. It communicates with the Wazuh server, sending data in near real-time through an encrypted and authenticated channel. The Wazuh agent provides capabilities such as log data collection, file integrity monitoring, threat detection, security configuration assessment, system inventory, vulnerability detection, and incident response to enhance your endpoint security.
 <img width="900" height="723" alt="image" src="https://github.com/user-attachments/assets/0760a2bb-66b1-4eee-b3ca-6db266a7ccc3" />

Wazuh agents are installed on endpoints such as laptops, desktops, servers, cloud instances, or virtual machines. They provide threat prevention, detection, and response capabilities.





Download & Install Wazuh Agent in Parrot OS
 <img width="900" height="777" alt="image" src="https://github.com/user-attachments/assets/4ed65f05-9860-4b4b-a035-a025a83baa31" />


Make sure your package manager is healthy
sudo apt update
sudo apt upgrade -y

Once your terminal responds normally and internet is working, install the Wazuh agent:
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.8.166' WAZUH_AGENT_NAME='parrot' dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
 <img width="900" height="571" alt="image" src="https://github.com/user-attachments/assets/3b485fbb-b0de-45f7-abeb-e5c946519665" />

Start the Agent
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
sudo systemctl status wazuh-agent
 
<img width="900" height="390" alt="image" src="https://github.com/user-attachments/assets/62804f7d-d769-4444-be11-b3901bcde43b" />




Dashboard Monitoring in Wazuh
After successfully installing the Wazuh Manager and connecting the Wazuh Agent, the next phase of the project involved monitoring system activity through the Wazuh Dashboard (Kibana interface). The dashboard provided real-time visibility into host and network security events collected from the agents.
 <img width="900" height="461" alt="image" src="https://github.com/user-attachments/assets/f4906ebb-ba3e-442e-b183-9271f1980c59" />

Key Monitoring Activities:
1.	Agent Status Monitoring:
Verified that the installed agents were properly registered and communicating with the Wazuh Manager. The dashboard displayed each agent’s connection status, last keep-alive time, and health metrics.
2.	Security Events and Alerts:
Monitored live alerts generated by the agents. These included failed login attempts (Event ID 4625), successful logins (4624), process creation (4688), and file access activities. The alerts were categorized by rule level and severity to identify potential threats.
3.	File Integrity Monitoring (FIM):
Observed alerts related to unauthorized file modifications in critical directories. This helped detect possible tampering or ransomware-like behaviour on monitored systems.
4.	System and Network Activity:
Reviewed data related to process execution, network connections, and user activity. The dashboard visualizations helped correlate suspicious behavior, such as unusual process chains or outbound network traffic.
 ![Uploading image.png…]()

5.	Authentication and Access Logs:
Filtered events in the dashboard to identify repeated authentication failures and login anomalies, which could indicate brute-force or credential-stuffing attempts.
6.	Rule Correlation and Threat Detection:
Analyzed alerts triggered by Wazuh’s predefined ruleset. The system correlated log data from multiple sources (Windows Event Logs, Syslog, and audit logs) to detect potential intrusions and misconfigurations.
7.	Dashboard Visualization and Reporting:
Used the Kibana interface to visualize data through bar graphs, pie charts, and timelines. Custom filters were applied to view trends over time, such as spikes in failed login attempts or configuration changes.
8.	Incident Verification and Response:
Cross-checked triggered alerts to confirm false positives and validated true incidents. Findings were documented for further incident response and security posture improvement.







WAZUH TROUBLESHOOTING & MITIGATION

Wazuh sometimes faces issues related to agent connection, log collection, rules, or dashboard. The troubleshooting and mitigation steps help ensure smooth monitoring and alerting.
________________________________________
1. Agent Not Connecting
Problem: Agent status shows disconnected or not sending logs.
Troubleshoot:
•	Check network connection to Wazuh Manager.
•	Verify agent key and configuration.
•	Check firewall ports 1514/1515.
Mitigation:
•	Re-register the agent with a new key.
•	Fix firewall/network issues.
________________________________________
2. Logs Not Arriving
Problem: No log data from agent.
Troubleshoot:
•	Check agent logs for permission errors.
•	Confirm the correct log file paths in ossec.conf.
Mitigation:
•	Correct file paths.
•	Give proper read permissions.
________________________________________
3. Rules Not Triggering
Problem: Alerts not generated.
Troubleshoot:
•	Test rules using ossec-logtest.
•	Check for syntax errors in rule files.
Mitigation:
•	Fix rule errors.
•	Restart Wazuh Manager.
________________________________________
4. Dashboard Not Showing Data
Problem: Wazuh dashboard / Kibana shows no logs.
Troubleshoot:
•	Check if indexer and dashboard services are running.
•	Look for index errors.
Mitigation:
•	Restart dashboard and indexer.
•	Recreate missing indices if needed.
________________________________________
5. File Integrity Monitoring Not Working
Problem: No alerts when files change.
Troubleshoot:
•	Check monitored paths.
•	Review syscheck logs.
Mitigation:
•	Add correct directories.
•	Restart the agent.
________________________________________
6. High CPU or Memory Usage
Problem: Wazuh runs slowly.
Troubleshoot:
•	Check system load.
•	Look for heavy rules or too many logs.
Mitigation:
•	Disable unnecessary rules.
•	Increase RAM/CPU if needed.
________________________________________
7. Active Response Not Running
Problem: Blocking actions or scripts not executed.
Troubleshoot:
•	Check active-response logs.
•	Ensure scripts have execute permission.
Mitigation:
•	Enable AR in config.
•	Fix script permissions.





CONCLUSION
Wazuh is a comprehensive open-source SIEM solution suitable for labs, small teams, and enterprise deployments. This project provided an overview of Wazuh architecture and features and included practical installation steps for deploying a monitoring instance on Kali Linux and installing the Wazuh agent on Windows. For production deployments, follow official Wazuh documentation for sizing, security hardening, and high-availability setups.
REFERENCES
1. Wazuh Documentation - https://documentation.wazuh.com/
2. Wazuh Downloads - https://wazuh.com/


