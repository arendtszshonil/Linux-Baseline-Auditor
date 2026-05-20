# Enterprise Linux Baseline Auditor

## Overview
An automated security auditing tool designed for Linux environments. This tool mimics the initial data-collection phases of endpoint detection agents by scraping raw system configurations and evaluating them against standard enterprise security baselines. 

## Technical Implementation
* **Collection Engine (Bash):** Utilizes native Linux binaries (`ss`, `grep`, `systemctl`) executing with elevated privileges to extract active network ports, parse authentication logs (`auth.log`/`secure`) for brute-force attempts, and map running system services.
* **Logic Engine (Python):** Ingests the raw text output from the collection phase, applying programmatic logic to identify insecure legacy protocols (e.g., Telnet, FTP), evaluate host-firewall status (UFW/Firewalld), and quantify SSH authentication failures.
* **Structured Export:** Packages the final audit findings into machine-readable JSON format, enabling seamless integration with centralized logging servers or SIEM dashboards.

## Security Value
This project demonstrates functional capabilities in Linux System Administration, Bash scripting, and programmatic data parsing. It proves the ability to automate tedious infrastructure auditing and translate raw system state into actionable, structured security intelligence.