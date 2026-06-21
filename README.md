# Network-Traffic-Analysis-Threat-Detection-Lab
Analyzed network traffic with Wireshark/Suricata to detect threats and map findings to MITRE ATT&amp;CK

# Network Threat Analysis & MITRE ATT&CK Mapping Report

**Target Host:** 10.0.0.5 (Production Web Server)  
**Attacking IP:** 203.0.113.44 (External Subnet)  
**Tools Evident:** Nikto Scanner Engine  

---

## Threat Event Breakdown & PCAP Analysis

| Packet Timestamp | Source IP | Traffic Action | Diagnostic Classification |
| :--- | :--- | :--- | :--- |
| `11:15:00` | `192.168.1.15` | `GET /index.html` | **False Positive** (Normal Employee Browsing) |
| `11:15:00` | `203.0.113.44` | `GET /robots.txt` | **True Positive** (Adversary Reconnaissance) |
| `11:15:01` | `203.0.113.44` | `GET /../../../../etc/passwd` | **True Positive** (Directory Traversal Attack) |

---

## MITRE ATT&CK Framework Mapping

### 1. Tactic: Reconnaissance (TA0043)
* **Technique:** Active Scanning (**T1595**)
* **Sub-technique:** Vulnerability Scanning (**T1595.002**)
* **Evidence:** The attacker deployed automated probing techniques using the `Nikto` scanning suite agent string directed at configuration root files (`/robots.txt`).

### 2. Tactic: Initial Access (TA0001) / Execution (TA0002)
* **Technique:** Exploit Public-Facing Application (**T1190**)
* **Evidence:** The adversary passed explicit relative string characters (`/../../../../etc/passwd`) inside open HTTP GET application vectors aiming to bypass service logical boundaries to read Linux core application hashes.

---

## Engineering Remediation Recommendations
1.  **Input Validation:** Sanitize application layer input strings explicitly rejecting generic pattern components like `../` or `/etc`.
2.  **User-Agent Filtering:** Configure local reverse proxies or Web Application Firewalls (WAF) to drop incoming connections from explicitly known malicious user-agent patterns like `Nikto` or `sqlmap`.
3.  **Principle of Least Privilege:** Ensure the user running the web server daemon process handles restricted DACL profiles so it cannot physically access `/etc/passwd`.
