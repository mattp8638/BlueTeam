import datetime

class VulnScanner:
    """
    Simulates a localized scanning agent that identifies vulnerabilities 
    and gathers specific forensic evidence (file paths, registry keys, processes).
    Outputs standard OCSF Class 2002 payloads.
    """
    
    @classmethod
    def run_scan(cls, target_device: dict) -> dict:
        """
        Simulates a scan against an endpoint. 
        In this mock, if the device is a Windows Server 2019, it 'finds' PrintNightmare.
        """
        print(f"\n[Vuln Scanner] Initiating scan against {target_device.get('hostname')} ({target_device.get('ip_address')})...")
        
        os_ver = target_device.get("os_version", "")
        
        # Simulate discovering CVE-2021-34527 (PrintNightmare)
        if "Windows" in target_device.get("os_family", "") and "2019" in os_ver:
            print("[Vuln Scanner] CRITICAL FINDING: Identified CVE-2021-34527 (PrintNightmare).")
            print("[Vuln Scanner] Gathering forensic evidence...")
            
            # Construct OCSF Class 2002 (Vulnerability Finding)
            finding = {
                "class_id": 2002,
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "severity": "Critical",
                "device": {
                    "uid": target_device.get("device_id"),
                    "ip": target_device.get("ip_address"),
                    "os": {"name": target_device.get("os_family"), "version": os_ver}
                },
                "vulnerabilities": [
                    {
                        "cve": {"uid": "CVE-2021-34527", "cvss_v3_score": 8.8},
                        "desc": "Windows Print Spooler Remote Code Execution Vulnerability"
                    }
                ],
                "enrichments": [
                    {
                        "name": "Forensic Evidence: Active Process",
                        "value": "spoolsv.exe (PID: 1450)",
                        "type": "process"
                    },
                    {
                        "name": "Forensic Evidence: Registry Misconfiguration",
                        "value": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint\\NoWarningNoElevationOnInstall = 1",
                        "type": "registry"
                    },
                    {
                        "name": "Forensic Evidence: Vulnerable DLL",
                        "value": "C:\\Windows\\System32\\spool\\drivers\\x64\\3\\mxdwdrv.dll (Version 10.0.17763.1)",
                        "type": "file"
                    }
                ]
            }
            return finding
            
        print("[Vuln Scanner] Scan completed. No critical vulnerabilities found.")
        return None
