# 🔔 Wazuh → n8n SOC Threat Detection Automation

[![Project Status](https://img.shields.io/badge/status-completed-brightgreen)](https://github.com/sri5hat/wazuh-n8n)  
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)  

Automated SOC workflow integrating **Wazuh**, **n8n**, and **VirusTotal** to monitor critical files, detect threats, and notify SOC teams efficiently.

---

## 📌 Workflow Diagram


**Workflow Overview:**

1. **Wazuh Agent** monitors critical directories for file creation or modification.  
2. **Wazuh Manager** triggers a custom Python script that calculates file hashes (SHA256/MD5/SHA1) and queries VirusTotal for threat intelligence.  
3. **n8n Workflow** processes alerts:  
   - Extracts Indicators of Compromise (IOC)  
   - Checks VirusTotal results  
   - Generates a structured summary  
   - Sends formatted HTML and Gmail alerts to SOC analysts  

This system enables SOC teams to receive **automated, actionable alerts** for potential threats efficiently.

---

## ⚡ Advantages

- **Real-Time Threat Detection:** Immediate monitoring and alerting for suspicious files.  
- **Automated IOC Extraction:** Reduces manual investigation workload.  
- **VirusTotal Integration:** Provides detailed file reputation analysis.  
- **SOC-Ready Alerts:** HTML and email notifications improve visibility and response time.  
- **Customizable & Scalable:** Easily extendable to monitor multiple directories or integrate with other tools.  
- **Hands-On Learning Experience:** Enhances skills in Wazuh, Python automation, n8n workflows, and threat intelligence processing.

---

## 📂 Folder References

- **Wazuh Agent Config:** [`wazuh-n8n/wazuh-agent`](wazuh-agent)  
- **Wazuh Manager Integration Scripts:** [`wazuh-n8n/wazuh-manager/integrations`](wazuh-manager/integrations)  
- **n8n Workflow Steps:** [`wazuh-n8n/n8n`](n8n)  
- **Documentation / Demo:** [`wazuh-n8n/docs`](docs)   


## 💡 Project Impact

This project showcases a **fully automated SOC workflow** integrating Wazuh, Python, n8n, and VirusTotal. It enables SOC teams to:

- **Detect threats in real-time** by monitoring critical files  
- **Reduce manual investigation efforts** with automated IOC extraction  
- **Respond faster** to suspicious or malicious files  
- **Centralize threat intelligence** and enhance visibility  
- **Scale easily** to monitor multiple directories or endpoints  
---

## 📌 References

- [Wazuh Documentation](https://documentation.wazuh.com/)  
- [n8n Documentation](https://docs.n8n.io/)  
- [VirusTotal API v3](https://developers.virustotal.com/reference)  
- [SOC Automation Best Practices](https://www.sans.org/white-papers/soc/)  

---

*Thank you for exploring the Wazuh → n8n SOC Threat Detection Automation project! *


