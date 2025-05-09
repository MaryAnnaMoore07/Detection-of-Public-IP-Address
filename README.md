# 🌐**Exposure of Critical Internal Services to the Internet**


![Brute Force Devices Exposed to the Internet](https://github.com/user-attachments/assets/9d08d0a3-57db-4e94-b597-97f90e2be438)

## Example Scenario:
During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources. An internal shared services device (e.g., a domain controller) is mistakenly exposed to the internet due to misconfiguration.

---

## Table:

| **Parameter** | **Description**                                                                                                |
| ------------- | -------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceInfo                                                                                                     |
| **Info**      | [Microsoft Defender Info](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)    |
| **Purpose**   | Contains contextual details like OS, network exposure, user sessions, and system roles for enrolled endpoints. |


---

### **Timeline Overview**  
📁 Misconfiguration Discovery:

**Findings:** infra-pki-01 was reachable via a public IP, exposing internal certificate services externally. Last confirmed exposure: 2025-02-14T13:42:10.354Z

Detection Queries:
1. **📁 Misconfiguration Discovery:**  
   - **Observed Behavior:**  Mm-mde-lab is not showing that it is internet-facing, but it has an open Public IP Address due to the results found`
  
   - **Detection Queries:**
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
```kql
DeviceInfo
| where DeviceName == "mm-mde-lab"
| where IsInternetFacing == true
| order by Timestamp desc
_____
<Query Results> None
```

### 🚫 Failed Login Attempts from External IPs
Multiple failed authentication events were traced back to international IP addresses trying to connect to the exposed VM.

```kql
DeviceLogonEvents
| where DeviceName == "mm-mde-lab"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

![image](https://github.com/user-attachments/assets/86ad6a42-b6b5-488d-ba0b-8e259422d159)

![image](https://github.com/user-attachments/assets/2e88e4ea-0281-4984-a987-5a32bfd08786)

---
The IP addresses of the top 4 most failed login attempts have not been able to successfully break into the VM.

```kql
let RemoteIPsInQuestion = dynamic(["94.102.52.73","185.243.96.116", "185.156.73.169", "92.63.197.9"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

**<Query Results> None**

---

**🔓 Any Successful Logons?**
The only successful remote/network logins in the last 7 days were for the ‘nack07’ account (4 total)

```kql
DeviceLogonEvents
| where DeviceName == "mm-mde-lab"
| where LogonType has_any("Network")
| where ActionType == "LogonSuccess"
| where AccountName == "nack07"
| summarize count()
```

There were zero (0) failed logins for the ‘nack07’ account, indicating that a brute force attempt for this account didn’t take place and a 1-time password guess is unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "mm-mde-lab"
| where LogonType has_any("Network")
| where ActionType == "LogonFailed"
| where AccountName == "nack07"
| summarize count()

```

---

We checked all the successful login IP Addresses for the ‘nack07’ account to see if any were unusual or from an unexpected location. All were normal. 

```kql
DeviceLogonEvents
| where DeviceName == "mm-mde-lab"
| where LogonType has_any("Network")
| where ActionType == "LogonSuccess"
| where AccountName == "nack07"
| summarize LoginCount = count()by DeviceName, ActionType, AccountName, RemoteIP

```

![image](https://github.com/user-attachments/assets/5288c4a9-86d4-431e-9609-ae0a8dfdceb8)


---
**🧠 Observations:**
Though the device did not show that it was internet-facing, it displayed a public IP Address, and clear brute force attempts had taken place. There is no evidence of any brute force success or unauthorized access from the legitimate account ‘nack07’. 

Here's how the relevant TTPs and detection elements can be organized into a chart for easy reference:

---

# 🧩 MITRE ATT&CK Techniques Observed for Incident Detection

| **TTP ID** | **Tactic / Technique**             | **Description**                                                       | **Detection Insight**                                                 |
| ---------- | ---------------------------------- | --------------------------------------------------------------------- | --------------------------------------------------------------------- |
| T1046      | Network Service Scanning           | Attackers may scan the PKI server for open services.                  | External scans against exposed PKI infrastructure.                    |
| T1110      | Brute Force                        | Repeated login failures from suspicious IPs.                          | Indicates brute-force attempt from multiple IPs.                      |
| T1071      | Application Layer Protocol         | Unauthorized traffic to HTTP/LDAP endpoints.                          | Unusual remote access attempts to certificate services.               |
| T1021      | Remote Services                    | External logins attempted via RDP or LDAP.                            | Attempts to access network services from public IPs.                  |
| T1075      | Pass the Hash                      | Possible hash reuse attempts inferred from failed interactive logons. | Failed remote interactive logons suggest password/hash-based attacks. |
| T1078      | Valid Accounts                     | Monitoring shows only valid user logons with no compromise.           | Detects misuse or anomalies in legitimate account logins.             |
| T1213      | Data from Information Repositories | Certificate data may be targeted during reconnaissance.               | Exposure of internal certificate services poses data discovery risks. |
---

This chart clearly organizes the MITRE ATT&CK techniques (TTPs) used in this incident, detailing their relevance to the detection process.

**📌 Response Actions Taken:**  

-Conducted endpoint and vulnerability scans

-Hardened network perimeter (disabled public IP, scoped NSG)

-Enabled logging on PKI endpoints

-Enforced lockout policies and MFA

-Scheduled recurring audits

---

## 🧪 Reproduction Steps:
1. Provision a virtual machine with a public IP address.
2. Ensure the device is actively communicating or available on the internet. (Test ping, etc.)
3. Onboard the device to Microsoft Defender for Endpoint.
4. Verify the relevant logs (e.g., network traffic logs, exposure alerts) are being collected in MDE.
5. Execute the KQL query in the MDE advanced hunting to confirm detection.

---

## Created By:
- **Author Name**: MaryAnna Moore  
- **Author Contact**: [LinkedIn](https://www.linkedin.com/in/maryanna-moore/)  
- **Date**: May 2025

## Validated By:
- **Reviewer Name**: Josh Madakor  
- **Reviewer Contact**: [LinkedIn](https://www.linkedin.com/in/joshmadakor/)  
- **Validation Date**: May 2025

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `May 2025`    | `MaryAnna Moore`   |
```
