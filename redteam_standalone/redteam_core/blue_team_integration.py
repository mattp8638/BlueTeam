from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DetectionEvent:
    event_id: str
    attack_id: str
    detection_type: str
    details: Dict[str, Any]
    severity: str
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BlueTeamIntegration:
    """Integration bridge between AI-RedTeaming and AI-BlueTeaming SIEM/EDR detection mechanisms."""

    def __init__(self) -> None:
        self.notifications: List[Dict[str, Any]] = []
        self.detection_events: List[DetectionEvent] = []

    def notify_blue_team(
        self,
        attack_id: str,
        module_name: str,
        action: str,
        target: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Notify BlueTeam SIEM/EDR of offensive action for correlation."""
        notification_id = f"notif-{uuid.uuid4().hex[:8]}"
        notification = {
            "notification_id": notification_id,
            "attack_id": attack_id,
            "module_name": module_name,
            "action": action,
            "target": target,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.notifications.append(notification)
        return notification_id

    def record_detection_event(
        self,
        attack_id: str,
        detection_type: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "Medium",
        confidence: float = 0.8,
    ) -> DetectionEvent:
        """Record a SIEM/EDR detection event triggered by red team activity."""
        event_id = f"det-{uuid.uuid4().hex[:8]}"
        event = DetectionEvent(
            event_id=event_id,
            attack_id=attack_id,
            detection_type=detection_type,
            details=details or {},
            severity=severity,
            confidence=confidence,
        )
        self.detection_events.append(event)
        return event

    def validate_detection(
        self,
        attack_id: str,
        expected_detections: List[str],
    ) -> Dict[str, Any]:
        """Compare actual detections against expected detection vectors."""
        actual_types = {e.detection_type for e in self.detection_events if e.attack_id == attack_id}
        detected = [d for d in expected_detections if d in actual_types]
        missed = [d for d in expected_detections if d not in actual_types]

        rate = len(detected) / len(expected_detections) if expected_detections else 0.0

        return {
            "attack_id": attack_id,
            "detection_rate": rate,
            "detected_detections": detected,
            "missed_detections": missed,
        }

    def get_purple_team_metrics(self) -> Dict[str, Any]:
        """Aggregate metrics for purple teaming assessment."""
        total_attacks = len({n["attack_id"] for n in self.notifications})
        total_detections = len(self.detection_events)
        rate = total_detections / total_attacks if total_attacks > 0 else (1.0 if total_detections > 0 else 0.0)

        return {
            "total_attacks": total_attacks,
            "total_notifications": len(self.notifications),
            "total_detections": total_detections,
            "detection_rate": min(1.0, rate),
        }
