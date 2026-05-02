# AWS GuardDuty Log Analysis using Splunk 🔐☁️

<img width="1324" height="458" alt="image" src="https://github.com/user-attachments/assets/da337137-1ef1-4ba6-a3c5-6d55e241abf4" />
<img width="1104" height="458" alt="image" src="https://github.com/user-attachments/assets/4e7e110e-1f11-4d01-94dc-9aad81cdd0d7" />

A hands-on **SOC-style cloud threat detection project** that demonstrates how to ingest **AWS GuardDuty findings (JSON logs)** into **Splunk Enterprise** and detect suspicious activities such as:

- Brute-force attacks
- Port scanning / reconnaissance
- Suspicious IAM API misuse
- Cryptocurrency mining / malware
- S3 misconfigurations / malicious access

This project simulates a **real-world cloud security monitoring workflow** and is ideal for **cybersecurity**, **cloud security**, **SOC analyst**, and **blue-team** learning.

---

## 📌 Project Overview

**AWS GuardDuty** is an AWS-native threat detection service that continuously monitors AWS accounts, workloads, and data for malicious or unauthorized activity.

In this project, I used **sample AWS GuardDuty findings** and ingested them into **Splunk Enterprise** to perform security investigations using **SPL (Search Processing Language)**.

### Key Goals
- Ingest GuardDuty JSON findings into Splunk
- Parse nested JSON fields
- Detect multiple categories of cloud threats
- Practice SOC-style log triage and threat hunting
- Build practical cloud detection engineering skills

---

## 🎯 Objectives

- Upload and index **AWS GuardDuty sample findings**
- Configure Splunk to correctly parse **JSON-based security alerts**
- Detect:
  - **EC2 SSH brute force**
  - **IAM Console login brute force**
  - **Reconnaissance / Port scans**
  - **Suspicious IAM API calls**
  - **Crypto mining / malware activity**
  - **S3 bucket misconfigurations**
- Query nested JSON fields using:
  - Native field extraction
  - `spath` for manual JSON parsing

---

## 🛠️ Tools & Technologies Used

- **Amazon GuardDuty** – Threat detection service (sample findings source)
- **Splunk Enterprise** – Log ingestion, search, and analysis platform
- **JSON Logs** – `guardduty_findings.json`
- **SPL (Splunk Search Processing Language)**
- **spath** – Nested JSON field extraction in Splunk

---

## 🧠 What is AWS GuardDuty?

**Amazon GuardDuty** is a threat detection and continuous security monitoring service in AWS.

It analyzes:
- **VPC Flow Logs** → Network traffic behavior
- **CloudTrail Logs** → API activity
- **DNS Logs** → Suspicious domain lookups

It uses:
- Machine learning
- Threat intelligence feeds
- Anomaly detection

to generate **security findings in JSON format**.

---

## 🚨 Threat Categories Covered

| Finding Type | Category | Description | Severity |
|---|---|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | Unauthorized Access | Repeated SSH brute-force attempts on EC2 | Medium |
| `Recon:EC2/Portscan` | Reconnaissance | External IP scanning EC2 for open ports | Low |
| `IAMUser/MaliciousIPCaller.Custom` | Suspicious API | IAM API calls from malicious IPs | Medium |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | Malware / Crypto | EC2 contacting crypto-mining pools | High |
| `S3/BucketAnonymousAccessGranted` | Misconfiguration | S3 bucket publicly accessible | Medium |

---

# 📂 Project Structure

```bash
AWS-GuardDuty-Log-Analysis-using-Splunk/
│
├── README.md
├── guardduty_findings.json
├── AWS GuardDuty Log Analysis using Splunk project Document.pdf
├── AWS GuardDuty Log Analysis using Splunk Project ScreenShots.pdf

````

> **Tip:** Create a `screenshots/` folder in your repo and export your PDF pages as PNG/JPG for a visually strong GitHub project page.

---

# ⚙️ Splunk Setup & Data Ingestion

## Step 1: Open Splunk Settings

Navigate to:

**Splunk Web → Settings → Add Data**

## Step 2: Choose Upload

Select the **Upload** method to import the local JSON file.

## Step 3: Upload the GuardDuty Log File

Upload:

```bash
guardduty_findings.json
```

## Step 4: Set Source Type

Set:

```bash
sourcetype = _json
```

## Step 5: Create / Select Index

Create and use:

```bash
guardduty_lab
```

## Step 6: Submit and Validate

After ingestion, validate that logs were successfully indexed:

```spl
index=guardduty_lab | head 5
```

---

# 🔍 Detection Use Cases & SPL Queries

---

## 1️⃣ Brute Force Attempts (EC2 & IAM Console)

### Objective

Detect:

* EC2 SSH brute-force attempts
* IAM Console login brute-force attempts

### SPL Query

```spl
index=guardduty_lab (type="UnauthorizedAccess:EC2/SSHBruteForce" OR type="UnauthorizedAccess:IAMUser/ConsoleLoginBruteForce")
| stats count AS attempts by resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, region, severity
| sort -attempts
```

### Why It Matters

* Identifies repeated login attempts
* Highlights attacker IPs
* Helps SOC analysts prioritize based on severity

---

## 2️⃣ Reconnaissance (Port Probes & Port Scans)

### Objective

Detect:

* Port scans
* Probes against exposed EC2 ports

### SPL Query

```spl
index=guardduty_lab (type="Recon:EC2/Portscan" OR type="Recon:EC2/PortProbeUnprotectedPort")
| stats count AS hits by resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, service.action.remoteIpDetails.country
| sort -hits
```

### Why It Matters

* Detects attacker pre-exploitation activity
* Shows source IPs and geolocation
* Helps identify scanning patterns

---

## 3️⃣ Suspicious API Calls (IAM Abuse)

### Objective

Detect:

* API calls from malicious IPs
* Unauthorized IAM activity

### SPL Query

```spl
index=guardduty_lab (type="IAMUser/MaliciousIPCaller.Custom" OR type="IAMUser/UnauthorizedAccess")
| stats count AS calls by resource.resourceType, service.action.remoteIpDetails.ipAddressV4, region, accountId
| sort -calls
```

### Why It Matters

* Detects possible credential theft
* Reveals suspicious API usage
* Useful for investigating privilege escalation attempts

---

## 4️⃣ Crypto Mining & Malware Activity

### Objective

Detect:

* Cryptocurrency mining
* DNS exfiltration
* Command-and-control (C2) communication

### SPL Query

```spl
index=guardduty_lab (type="CryptoCurrency:EC2/BitcoinTool.B!DNS" OR type="Trojan:EC2/DNSDataExfiltration" OR type="Backdoor:EC2/C&CActivity.B")
| stats count AS detections by resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, severity
| sort -detections
```

### Why It Matters

* Detects compromised EC2 workloads
* Identifies high-severity malicious activity
* Useful for immediate containment and investigation

---

## 5️⃣ S3 Misconfigurations & Malicious Access

### Objective

Detect:

* Publicly exposed S3 buckets
* S3 access from malicious IPs

### SPL Query

```spl
index=guardduty_lab (type="S3/MaliciousIPCaller" OR type="S3/BucketAnonymousAccessGranted")
| stats count AS findings by resource.resourceType, resource.instanceDetails.instanceId, service.action.remoteIpDetails.ipAddressV4, region
| sort -findings
```

### Why It Matters

* Detects risky S3 exposure
* Highlights potential data leak scenarios
* Common and high-impact AWS misconfiguration class

---

# 🧩 Optional: Querying Nested JSON Fields with `spath`

Since GuardDuty logs contain **nested JSON**, you can explicitly extract fields using `spath`.

### Example

```spl
index=guardduty_lab
| spath path=service.action.remoteIpDetails.ipAddressV4 output=src_ip
| spath path=resource.instanceDetails.instanceId output=instance_id
| table _time type src_ip instance_id severity region
```

### Use Cases

* Manual nested field extraction
* Custom dashboard building
* Handling inconsistent field auto-parsing

---

# 📊 Key Findings

Through analysis of GuardDuty findings in Splunk, this project successfully identified:

* **Brute-force attacks** against EC2 and IAM
* **Reconnaissance activity** via port scans and probes
* **Suspicious IAM/API activity** from malicious sources
* **Crypto mining / malware indicators** including DNS-based detection
* **S3 misconfigurations** such as public bucket exposure

---

# 🛡️ Incident Response Recommendations

## For Brute Force Attacks

* Block malicious source IPs using Security Groups / NACL / WAF
* Disable password-based SSH authentication
* Enforce MFA for IAM users
* Rotate compromised credentials

## For Port Scanning

* Restrict exposed ports
* Harden Security Groups
* Apply least-privilege network access
* Correlate with VPC Flow Logs

## For Suspicious IAM/API Calls

* Review CloudTrail for full API history
* Revoke/rotate IAM credentials
* Apply least privilege
* Use IAM Access Analyzer

## For Crypto Mining / Malware

* Isolate affected EC2 instances
* Capture forensic evidence
* Inspect outbound DNS and running processes
* Rebuild compromised instances if needed

## For S3 Misconfigurations

* Remove public access immediately
* Enable **Block Public Access**
* Audit bucket policies and ACLs
* Review access logs and exposed objects

---


# 🚀 How to Reproduce This Project

## 1. Install Splunk Enterprise

Set up a local Splunk Enterprise instance.

## 2. Download GuardDuty Sample Findings

Use a sample GuardDuty JSON findings file:

```bash
guardduty_findings.json
```

## 3. Upload the File to Splunk

* Go to **Settings → Add Data**
* Choose **Upload**
* Select the JSON file
* Set:

  * `sourcetype = _json`
  * `index = guardduty_lab`

## 4. Validate Ingestion

```spl
index=guardduty_lab | head 5
```

## 5. Run Detection Queries

Use the SPL queries from the **Detection Use Cases** section.

---

# 💡 Skills Demonstrated

* Cloud Security Monitoring
* AWS GuardDuty Analysis
* Splunk Log Ingestion
* Splunk SPL Querying
* JSON Field Parsing
* SOC Threat Hunting
* Detection Engineering
* Security Triage
* Incident Response Thinking
* Blue Team Workflow

---

# 🎓 Learning Outcomes

By completing this project, I developed hands-on experience in:

* Ingesting structured **cloud security logs** into Splunk
* Working with **nested JSON fields**
* Writing **SOC-style SPL detections**
* Understanding **AWS GuardDuty finding types**
* Investigating cloud threats across:

  * Compute
  * IAM
  * Networking
  * Storage (S3)

---

# 📌 Use Cases / Real-World Relevance

This project is highly relevant for roles such as:

* **SOC Analyst**
* **Cloud Security Analyst**
* **Cybersecurity Analyst**
* **Detection Engineer**
* **Blue Team Intern / Associate**
* **Splunk Security Analyst**

---

# 🔮 Future Enhancements

* Build a **Splunk dashboard** for GuardDuty detections
* Add **severity-based alerting**
* Correlate GuardDuty findings with:

  * CloudTrail
  * VPC Flow Logs
  * AWS Config
* Create **scheduled alerts** in Splunk
* Export detections into **MITRE ATT&CK mapping**
* Integrate with **SOAR / response workflows**

---

# 📚 References

* [AWS GuardDuty Documentation](https://docs.aws.amazon.com/guardduty/)
* [Splunk Enterprise Documentation](https://docs.splunk.com/Documentation/Splunk)
* [Splunk SPL Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)


# 📜 License

This project is for **educational and portfolio purposes**.

````
