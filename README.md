# 🔔 Wazuh → n8n SOC Threat Detection Automation

[![Project Status](https://img.shields.io/badge/status-completed-brightgreen)](https://github.com/sri5hat/wazuh-n8n)  
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)  

Automated SOC workflow integrating **Wazuh**, **n8n**, and **VirusTotal** to monitor critical files, detect threats, and notify SOC teams efficiently.

---
## 📌 Workflow Diagram
<p align="center">
  <img src="https://github.com/user-attachments/assets/0d0dde69-5f56-40d9-bec6-af6d6308af61" width="650">
</p>


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

## ⚙️ n8n Workflow Nodes (Detailed Documentation)

This section explains every node used in the Wazuh → n8n → VirusTotal → Gmail workflow, including configuration and code. 

## 1️⃣ Webhook Node — Receive Wazuh Alerts

Purpose:
Receives alerts directly from the Wazuh Manager.

Configuration: 

| Setting       | Value                   |
| ------------- | ----------------------- |
| HTTP Method   | `POST`                  |
| Response Mode | `On Received`           |
| Webhook URL   | `/webhook-test/filetxt` |


## 2️⃣ Extract IOC Node — Parse Wazuh IOC Details

Purpose:
Extract file information (path + hash) from Wazuh alert JSON.

Code: 
```javascript
// Extract syscheck info safely
const alert = $json.body.full_alert?.syscheck || {};

return [{
  file_path: alert.path || "N/A",
  file_hash: alert.sha256_after || alert.md5_after || alert.sha1_after || null,
  agent_name: $json.body.agent_name,
  description: $json.body.description,
  rule_id: $json.body.rule_id,
  timestamp: $json.body.timestamp
}];
```

## 3️⃣ VirusTotal Node — Check File Reputation

Purpose:
Uses VirusTotal API to check the reputation of the file hash.

Configuration:

| Setting        | Value                                                            |
| -------------- | ---------------------------------------------------------------- |
| HTTP Method    | `GET`                                                            |
| URL            | `https://www.virustotal.com/api/v3/files/{{$json["file_hash"]}}` |
| Authentication | API Key (Header)                                                 |


```json
{
  "x-apikey": "YOUR_API_KEY_HERE"
}
```
## 4️⃣ Generate File Summary Node — Merge IOC + VT Results

Purpose:
Create a structured SOC summary from Wazuh IOC + VirusTotal response.

Code:
```javascript
// Step 1: Get file_path from Extract IOC node
const extractIOC = $("Extract IOC").item;
const file_path = extractIOC?.json?.file_path || "Unknown";

// Step 2: Merge VirusTotal + IOC data
return $input.all().map(item => {
  const vtData = item.json;
  const iocData = item.binary?.Extract_IOC_json
    ? JSON.parse(item.binary.Extract_IOC_json.data.toString())
    : (item.json.Extract_IOC || item.json.ioc || item.json || {});

  const file_hash =
    iocData.file_hash ||
    vtData.file_hash ||
    vtData.data?.id ||
    vtData.attributes?.sha256 ||
    null;

  const attributes = vtData.data?.attributes || vtData.attributes || {};
  const vt_stats = attributes.last_analysis_stats || {};

  const malicious_count = vt_stats.malicious || 0;
  const malicious = malicious_count > 0;

  const sigma = attributes.sigma_analysis_results?.[0] || {};
  const sigma_rule_title = sigma.rule_title || "No Sigma rule";
  const sigma_rule_description = sigma.rule_description || "No Sigma description";

  return {
    json: {
      file_path,
      file_hash,
      agent_name: iocData.agent_name || "Unknown",
      description: iocData.description || "No description",
      rule_id: iocData.rule_id || "N/A",
      vt_stats: {
        malicious: vt_stats.malicious || 0,
        suspicious: vt_stats.suspicious || 0,
        undetected: vt_stats.undetected || 0,
        harmless: vt_stats.harmless || 0,
        timeout: vt_stats.timeout || 0
      },
      malicious,
      malicious_count,
      verdict: malicious ? "MALICIOUS" : "CLEAN",
      emoji: malicious ? "🚨" : "✅",
      vt_link: file_hash
        ? `https://www.virustotal.com/gui/file/${file_hash}/detection`
        : "N/A",
      sigma_rule_title,
      sigma_rule_description,
      timestamp: new Date().toISOString()
    }
  };
});
``` 
## 5️⃣ HTML Template Node — Build SOC Email Alert

Purpose:
Generate a visually appealing HTML email for SOC analysts.

HTML Code: 
```HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>🔔 SOC Threat Alert</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f5f6fa; color: #2d3436; padding: 20px; }
  .container { background: #ffffff; border-radius: 12px; box-shadow: 0 0 8px rgba(0,0,0,0.1); padding: 20px; max-width: 600px; margin: auto; }
  h2 { color: #2d3436; text-align: center; border-bottom: 2px solid #0984e3; padding-bottom: 10px; }
  table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 15px; }
  th, td { padding: 10px; border-bottom: 1px solid #dcdde1; text-align: left; }
  th { background-color: #0984e3; color: white; }
  .malicious { color: #d63031; font-weight: bold; }
  .clean { color: #00b894; font-weight: bold; }
  a { color: #0984e3; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .footer { text-align: center; font-size: 0.8em; color: #636e72; margin-top: 20px; }
</style>
</head>
<body>
  <div class="container">
    <h2>🚨 SOC Threat Intelligence Alert</h2>
    <p>Hello SOC Team,</p>
    <p>A new file alert has been triggered. Below are the analysis details:</p>
    <table>
      <tr><th>File Path</th><td>{{ $json["file_path"] }}</td></tr>
      <tr><th>File Hash</th><td>{{ $json["file_hash"] }}</td></tr>
      <tr>
        <th>Verdict</th>
        <td class="{{ $json["malicious"] ? "malicious" : "clean" }}">
          {{ $json["verdict"] }} {{ $json["emoji"] }}
        </td>
      </tr>
      <tr><th>Malicious Detections</th><td>{{ $json["vt_stats"]["malicious"] }}</td></tr>
      <tr><th>Suspicious</th><td>{{ $json["vt_stats"]["suspicious"] }}</td></tr>
      <tr><th>Undetected</th><td>{{ $json["vt_stats"]["undetected"] }}</td></tr>
      <tr><th>VirusTotal Link</th><td><a href="{{ $json["vt_link"] }}">View Report</a></td></tr>
    </table>
    <p class="footer">SOC Automated Alert • Generated at {{ $json["timestamp"] }}</p>
  </div>
</body>
</html>
```
## 6️⃣ Gmail Notification Node — Send the Alert

Purpose:
Send the HTML SOC report to the security team.

Configuration: 

| Setting    | Value                          |
| ---------- | ------------------------------ |
| Node Type  | Gmail → Send Email             |
| Subject    | `🚨 SOC Threat Alert`          |
| HTML Body  | Output from HTML Template node |
| Recipients | SOC Team Email                 |

```json
{{$node["HTML"].json["html"]}}
```

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


