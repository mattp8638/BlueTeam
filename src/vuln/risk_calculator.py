import math
import json

class VulnerabilityRiskCalculator:
    def __init__(self):
        # Weight configurations defined in the architectural specifications
        self.w_cvss = 0.40
        self.w_epss = 0.25
        self.w_kev = 0.35
        self.escalation_threshold = 8.5

    def calculate_risk_score(self, cvss_base: float, epss_score: float, is_kev_listed: bool) -> float:
        """
        Calculates the dynamic Risk Score (RS) using the formula:
        RS = (w1 * CVSS) + (w2 * ln(EPSS)) + (w3 * KEV_Factor)
        """
        # Protect against ln(0) if epss is exactly 0
        safe_epss = max(epss_score, 0.00001)
        
        # Calculate KEV factor
        kev_factor = 10.0 if is_kev_listed else 0.0
        
        # Apply the formula
        part_cvss = self.w_cvss * cvss_base
        part_epss = self.w_epss * math.log(safe_epss)
        part_kev = self.w_kev * kev_factor
        
        rs = part_cvss + part_epss + part_kev
        
        # Normalize score between 0 and 10 (ln(epss) can be highly negative)
        return max(0.0, min(10.0, rs))

    def evaluate_vulnerability(self, vuln_data: dict) -> dict:
        """
        Evaluates an OCSF Class 2002 vulnerability finding payload.
        """
        cvss = vuln_data.get("vulnerability", {}).get("cvss_base_score", 0.0)
        epss = vuln_data.get("vulnerability", {}).get("epss_score", 0.00001)
        kev = vuln_data.get("vulnerability", {}).get("cisa_kev_listed", False)
        
        risk_score = self.calculate_risk_score(cvss, epss, kev)
        
        result = {
            "cve_id": vuln_data.get("vulnerability", {}).get("cve_id", "UNKNOWN"),
            "calculated_risk_score": round(risk_score, 2),
            "requires_escalation": risk_score >= self.escalation_threshold
        }
        
        if result["requires_escalation"]:
            self._trigger_soar_escalation(result)
            
        return result

    def _trigger_soar_escalation(self, result: dict):
        """Mock function simulating an API webhook to the SOAR core."""
        print(f"[!] ESCALATION TRIGGERED! Threshold {self.escalation_threshold} exceeded.")
        print(f"    Payload dispatched to SOAR engine for CVE: {result['cve_id']} (Score: {result['calculated_risk_score']})")


if __name__ == "__main__":
    calculator = VulnerabilityRiskCalculator()
    
    # Test Scenario 1: High CVSS, High EPSS, Active KEV (Should Trigger Escalation)
    mock_vuln_1 = {
        "activity_id": 2002,
        "vulnerability": {
            "cve_id": "CVE-2026-3262",
            "cvss_base_score": 7.5,
            "epss_score": 0.8421,
            "cisa_kev_listed": True
        }
    }
    
    # Test Scenario 2: High CVSS, Low EPSS, Not in KEV (Should NOT trigger)
    mock_vuln_2 = {
        "activity_id": 2002,
        "vulnerability": {
            "cve_id": "CVE-2026-9999",
            "cvss_base_score": 9.8,
            "epss_score": 0.001,
            "cisa_kev_listed": False
        }
    }
    
    print("Evaluating Mock Vulnerability 1 (CVE-2026-3262)...")
    res1 = calculator.evaluate_vulnerability(mock_vuln_1)
    print(json.dumps(res1, indent=2))
    
    print("\nEvaluating Mock Vulnerability 2 (CVE-2026-9999)...")
    res2 = calculator.evaluate_vulnerability(mock_vuln_2)
    print(json.dumps(res2, indent=2))
