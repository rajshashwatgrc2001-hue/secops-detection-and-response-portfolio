from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List

app = FastAPI(title="Agentic SOC Triage API", version="1.0.0")

class AlertPayload(BaseModel):
    alert_id: str
    event_name: str
    source_ip: str
    destination_ip: str
    user_identity: str
    raw_log: str

class TriageReport(BaseModel):
    alert_id: str
    mitre_technique_id: str
    mitre_technique_name: str
    risk_score: float
    reasoning: str
    recommended_action: str

# MITRE ATT&CK Context Lookup
MITRE_DB = {
    "ConsoleLogin": {"id": "T1078", "name": "Valid Accounts"},
    "AssumeRoleWithWebIdentity": {"id": "T1550", "name": "Use Alternate Authentication Material"},
    "DisableSecurityHub": {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"},
    "StopLogging": {"id": "T1562.001", "name": "Impair Defenses: Disable Cloud Logging"}
}

@app.post("/triage", response_model=TriageReport)
async def triage_alert(alert: AlertPayload):
    technique = MITRE_DB.get(alert.event_name, {"id": "T1059", "name": "Command and Scripting Interpreter"})
    
    # Autonomous heuristic risk scoring
    risk_score = 8.5 if "Disable" in alert.event_name or "Stop" in alert.event_name else 4.5
    
    return TriageReport(
        alert_id=alert.alert_id,
        mitre_technique_id=technique["id"],
        mitre_technique_name=technique["name"],
        risk_score=risk_score,
        reasoning=f"Agent parsed '{alert.event_name}' for identity {alert.user_identity}. Pattern correlates with adversary persistence/defense evasion.",
        recommended_action="Revoke active IAM session credentials and isolate target workload immediately."
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
