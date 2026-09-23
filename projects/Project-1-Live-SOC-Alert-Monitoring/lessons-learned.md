
## Alert #1
# Incident SOC344: EDR Tampering & Evasion Attempt

### Key Takeaways
* **Legitimate Infrastructure Abuse:** Attackers frequently leverage trusted third-party services and CDN platforms (such as GitHub) to host and deliver malicious payloads. This highlights that IP reputation checks alone are insufficient and must be combined with deep endpoint and process behavior analysis.
* **Process Execution Monitoring:** Early detection of suspicious command-line arguments (e.g., attempts to suspend EDR agents via utilities like `WerFaultSecure.exe`) is critical for stopping defense evasion before execution succeeds.
* **Incident Response Efficiency:** Prompt host containment (`WS-Prod-02`) effectively prevented any lateral movement or wider internal propagation across the corporate network.

### MITRE ATT&CK Mapping & Threat Analysis
* **Defense Evasion (T1562.001):** Attempts to impair defenses by suspending or modifying local security tools.
* **Execution (T1059.001):** Use of command-line interpreters (PowerShell) for payload staging and execution.
* **Ingress Tool Transfer (T1105):** Pulling external binaries directly from external CDN infrastructure.

### Recommendations
* Enforce stricter application control and egress filtering policies to restrict unauthorized external downloads.
* Implement continuous monitoring and immediate alerting for unexpected service or security tool termination events.





## Alert #2
## Incident 2: Web Application Exploitation & Reconnaissance

### Key Takeaways
* **Web-Based Attack Vector:** The incident began with an HTTP POST request targeting a vulnerable endpoint on a corporate server, demonstrating how attackers use web applications as an entry point.
* **Post-Exploitation Discovery:** Identified malicious post-exploitation behavior where command-line tools and system enumeration commands were executed immediately following the initial web request to explore the system environment.

### MITRE ATT&CK Mapping & Threat Analysis
* **Exploit Public-Facing Application (T1190):** Initial access gained through an exploited vulnerability in a public-facing web application.
* **Command and Scripting Interpreter: Windows Command Shell (T1059.003):** Use of Windows command-line shells to execute commands on the compromised host.
* **Process Discovery (T1057):** Enumerating running processes to understand active security tools or environment context.
* **File and Directory Discovery (T1083):** Searching for files, directories, or system internals (such as checking `c:\temp` or using `dir`) to plan subsequent actions.

### Recommendations
* Update and properly configure Web Application Firewalls (WAF) to filter malicious HTTP POST payloads and block common injection or exploit patterns.
* Ensure timely patching and vulnerability management for all corporate web applications and underlying software.
* Implement process execution controls to prevent web server or application services from spawning unauthorized command-line shells (`cmd.exe`, `powershell.exe`).