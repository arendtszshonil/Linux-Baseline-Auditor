import os
import json
import datetime

def analyze_ssh(file_path):
    # count the failed ssh login attempts to detect potential brute force attacks
    if not os.path.exists(file_path):
        return "error: ssh log file not found."

    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    failed_attempts = len(lines)
    if failed_attempts == 0:
        return "pass: 0 failed ssh logins detected."
    elif failed_attempts < 10:
        return f"warning: {failed_attempts} failed ssh logins. monitor closely."
    else:
        return f"flag: {failed_attempts} failed ssh logins. potential brute force attack in progress."

def analyze_ports(file_path):
    # parse the active listening ports. flag insecure legacy protocols like telnet (23) or ftp (21).
    if not os.path.exists(file_path):
        return ["error: port scan file not found."]

    insecure_ports = [":21", ":23"]
    findings = []

    with open(file_path, 'r') as f:
        for line in f:
            for port in insecure_ports:
                if port in line:
                    findings.append(f"flag: insecure port {port.strip(':')} is actively listening.")
    
    if not findings:
        return ["pass: no standard insecure legacy ports detected."]
    return findings

def analyze_services(file_path):
    # check if critical security services are running (e.g., host firewalls)
    if not os.path.exists(file_path):
        return ["error: services file not found."]
        
    findings = []
    with open(file_path, 'r') as f:
        content = f.read().lower()
        
        if "ufw.service" not in content and "firewalld.service" not in content:
            findings.append("flag: no standard host firewall service (ufw/firewalld) appears to be running.")
        else:
            findings.append("pass: host firewall service is active.")
            
    return findings

def main():
    print("\n--- enterprise baseline security report ---")
    
    ssh_result = analyze_ssh('failed_ssh.txt')
    port_results = analyze_ports('active_ports.txt')
    service_results = analyze_services('running_services.txt')
    
    print("\n[1] ssh authentication audit")
    print(f"  - {ssh_result}")
    
    print("\n[2] network port audit")
    for res in port_results:
        print(f"  - {res}")
        
    print("\n[3] system service audit")
    for res in service_results:
        print(f"  - {res}")
        
    print("\n--- audit complete ---\n")

    # package the findings into a structured dictionary and export to json
    report_data = {
        "scan_timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host_environment": "linux",
        "findings": {
            "ssh_audit": ssh_result,
            "port_audit": port_results,
            "service_audit": service_results
        }
    }

    with open("audit_report.json", "w") as json_file:
        json.dump(report_data, json_file, indent=4)
        
    print("[+] structured data exported to: audit_report.json")

if __name__ == "__main__":
    main()