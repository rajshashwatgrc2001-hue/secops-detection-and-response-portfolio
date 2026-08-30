from typing import Dict

class RiskBasedAlertingEngine:
    def __init__(self, threshold: int = 100):
        self.threshold = threshold
        self.entity_risk_table: Dict[str, int] = {}

    def process_event(self, entity_id: str, risk_score: int, rule_name: str) -> Dict:
        current_score = self.entity_risk_table.get(entity_id, 0) + risk_score
        self.entity_risk_table[entity_id] = current_score
        
        triggered = current_score >= self.threshold
        return {
            "entity_id": entity_id,
            "accumulated_risk_score": current_score,
            "threshold_breached": triggered,
            "action": "Trigger SOC Alert" if triggered else "Log & Monitor"
        }

if __name__ == "__main__":
    engine = RiskBasedAlertingEngine(threshold=100)
    # Event 1: Recon (Score 40)
    print(engine.process_event("user:admin_temp", 40, "AWS IAM Policy Discovery"))
    # Event 2: Defense Evasion (Score 70) -> Total 110 (Breach)
    print(engine.process_event("user:admin_temp", 70, "AWS CloudTrail Logging Disabled"))
