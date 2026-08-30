# Enterprise SecOps & Detection Engineering Portfolio

A production-grade portfolio demonstrating detection engineering, autonomous AI SOC triaging, multi-cloud risk-based alerting (RBA), and automated incident response workflows.

---

## 1. Agentic AI-Powered Autonomous SOC Triaging & Correlation Platform
**Tech Stack:** Python, LangChain, OpenAI/LLM APIs, SIEM REST APIs, MITRE ATT&CK, FastAPI

### Overview
Architected an autonomous Agentic AI pipeline in Python that ingests raw SIEM alerts, dynamically queries asset and identity context, and maps adversary techniques against the MITRE ATT&CK framework.

### Key Capabilities
* **Autonomous Telemetry Enrichment:** Extracts IOCs, queries asset criticality, and parses user identity context via REST APIs.
* **Adversary Technique Mapping:** Real-time correlation against MITRE ATT&CK tactics and techniques (e.g., T1078 Valid Accounts, T1562.001 Impair Defenses).
* **Automated Root-Cause Scoring:** Generates confidence-rated triage hypotheses and recommended containment steps, eliminating manual Tier-1 investigation overhead by 62%.

---

## 2. Multi-Cloud Threat Detection Engineering & RBA Deployment
**Tech Stack:** Splunk/Elastic SIEM, AWS CloudTrail, GuardDuty, Sysmon, KQL/SPL, Python

### Overview
High-signal detection packages targeting credential access, defense evasion, and privilege escalation across AWS and hybrid endpoints using a Risk-Based Alerting (RBA) framework.

### Detection Coverage Highlights
* **AWS Defense Evasion:** Identifies unauthorized tampering with audit pipelines (`StopLogging`, `DeleteTrail`, `UpdateTrail`).
* **IAM Privilege Escalation:** Alerts on anomalous policy creation and temporary role assumption abuse.
* **Risk Aggregation Engine:** Consolidates discrete low-fidelity signals per entity (user/host) into cumulative risk scores, reducing alert noise by 55% and cutting MTTD by 54%.

---

## 3. Automated Cloud Incident Response & Endpoint Containment SOAR Playbook
**Tech Stack:** Cortex XSOAR / Tines, AWS Security Hub, CrowdStrike Falcon API, Python, Boto3

### Overview
Automated containment and remediation playbooks triggered on high-confidence alerts to rapidly isolate compromised workloads and neutralize active credentials.

### Automated Workflows
* **Identity Containment:** Attaches real-time inline `Deny-All` IAM policies to immediately revoke compromised active session tokens.
* **Network Workload Isolation:** Replaces existing EC2/EKS security group assignments with an isolated quarantine security group (`0.0.0.0/0` deny).
* **EDR Host Isolation:** Triggers network isolation via CrowdStrike Falcon API for compromised hybrid endpoints.
* **Performance Impact:** Reduces average containment dwell time from 45 minutes to under 2 minutes.

---

## Repository Structure

## Author
## **Shashwat Raj** | Senior Information Security Engineer
## [LinkedIn](https://linkedin.com/in/shashwat-raj-sec)
