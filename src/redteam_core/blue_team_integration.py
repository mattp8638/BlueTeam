from typing import Dict, List, Any, Optional, Tuple, Set, Union
"""
Blue Team Integration

Integration between AI-RedTeaming and AI-BlueTeaming platforms.
This enables collaborative purple teaming exercises.
"""

import json
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass


@dataclass
class DetectionEvent:
    """Represents a detection event from the BlueTeam"""
    event_id: str
    attack_id: str
    detection_type: str
    timestamp: datetime
    details: Dict[str, Any]
    severity: str
    confidence: float


class BlueTeamIntegration:
    """
    Integration between AI-RedTeaming and AI-BlueTeaming platforms.
    
    This module provides:
    - Real-time notification of red team activities to blue team
    - Detection validation (did blue team detect our attacks?)
    - Collaborative incident response
    - Purple team exercise coordination
    - Metrics collection for both teams
    
    The integration enables:
    - Red team to test blue team detection capabilities
    - Blue team to validate their defenses against real attacks
    - Joint exercises with automated validation
    - Continuous improvement of both teams
    """
    
    def __init__(self, nerve_center=None):
        """
        Initialize the Blue Team Integration.
        
        Args:
            nerve_center: Reference to the BlueTeam NerveCenter
        """
        self.nerve_center = nerve_center
        self.detection_events: Dict[str, DetectionEvent] = {}
        self.red_team_notifications: List[Dict[str, Any]] = []
        self.purple_team_metrics: Dict[str, Any] = {
            'detection_rate': 0.0,
            'false_positives': 0,
            'false_negatives': 0,
            'mean_time_to_detect': 0.0,
            'total_attacks': 0,
            'detected_attacks': 0
        }
    
    def notify_blue_team(
        self, 
        attack_id: str, 
        module_name: str, 
        action: str, 
        target: str, 
        details: Dict[str, Any] = None
    ) -> str:
        """
        Notify the BlueTeam of a red team action.
        
        This sends a notification to the BlueTeam SIEM for detection validation.
        
        Args:
            attack_id: ID of the red team operation
            module_name: Name of the attack module being executed
            action: Description of the action
            target: Target of the action
            details: Additional details about the action
            
        Returns:
            str: Notification ID
        """
        notification_id = f"redteam-notify-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc)
        
        notification = {
            'notification_id': notification_id,
            'attack_id': attack_id,
            'module_name': module_name,
            'action': action,
            'target': target,
            'timestamp': timestamp.isoformat(),
            'details': details or {},
            'status': 'SENT'
        }
        
        self.red_team_notifications.append(notification)
        
        # If we have a nerve center, route the event through it
        if self.nerve_center:
            try:
                # Create a synthetic event that looks like it came from a real source
                event_data = {
                    'class_id': 1001,  # Malware Finding (for testing)
                    'severity': 'High',
                    'activity_name': f'RedTeam Activity: {action}',
                    'src_endpoint_ip': target,
                    'file_path': f'/redteam/{module_name}',
                    'redteam_operation': attack_id,
                    'redteam_module': module_name,
                    'redteam_action': action,
                    'timestamp': timestamp.isoformat()
                }
                
                # Route through the nerve center
                self.nerve_center.route_event(
                    source_type='REDTEAM_NOTIFICATION',
                    raw_data=event_data,
                    device_context={'ip_address': target, 'device_id': f'redteam-{attack_id}'}
                )
                
                notification['status'] = 'DELIVERED'
                
            except Exception as e:
                notification['status'] = 'FAILED'
                notification['error'] = str(e)
        
        print(f"[BlueTeam Integration] Notification sent: {notification_id}")
        print(f"[BlueTeam Integration] Attack: {attack_id}, Module: {module_name}, Action: {action}")
        
        return notification_id
    
    def record_detection_event(
        self, 
        attack_id: str, 
        detection_type: str, 
        details: Dict[str, Any], 
        severity: str = "Medium",
        confidence: float = 0.8
    ) -> DetectionEvent:
        """
        Record a detection event from the BlueTeam.
        
        Args:
            attack_id: ID of the red team operation that was detected
            detection_type: Type of detection (e.g., 'SIEM', 'EDR', 'IDS')
            details: Details about the detection
            severity: Severity of the detection
            confidence: Confidence score (0.0 to 1.0)
            
        Returns:
            DetectionEvent: The recorded detection event
        """
        event_id = f"detection-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc)
        
        event = DetectionEvent(
            event_id=event_id,
            attack_id=attack_id,
            detection_type=detection_type,
            timestamp=timestamp,
            details=details,
            severity=severity,
            confidence=confidence
        )
        
        self.detection_events[event_id] = event
        
        # Update purple team metrics
        self._update_metrics(attack_id, True, confidence)
        
        print(f"[BlueTeam Integration] Detection recorded: {event_id}")
        print(f"[BlueTeam Integration] Attack: {attack_id}, Type: {detection_type}, Confidence: {confidence}")
        
        return event
    
    def record_missed_detection(self, attack_id: str, reason: str = "") -> str:
        """
        Record that an attack was not detected by the BlueTeam.
        
        Args:
            attack_id: ID of the red team operation that was missed
            reason: Reason for the missed detection
            
        Returns:
            str: ID of the missed detection record
        """
        record_id = f"missed-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc)
        
        record = {
            'record_id': record_id,
            'attack_id': attack_id,
            'timestamp': timestamp.isoformat(),
            'reason': reason,
            'status': 'CONFIRMED_MISSED'
        }
        
        # Update purple team metrics
        self._update_metrics(attack_id, False, 0.0)
        
        print(f"[BlueTeam Integration] Missed detection recorded: {record_id}")
        print(f"[BlueTeam Integration] Attack: {attack_id}, Reason: {reason}")
        
        return record_id
    
    def validate_detection(
        self, 
        attack_id: str, 
        expected_detections: List[str]
    ) -> Dict[str, Any]:
        """
        Validate if the BlueTeam detected the expected red team activities.
        
        Args:
            attack_id: ID of the red team operation
            expected_detections: List of detection types we expect
            
        Returns:
            Dict: Validation results
        """
        # Get all detection events for this attack
        attack_detections = [
            event for event in self.detection_events.values()
            if event.attack_id == attack_id
        ]
        
        # Check which expected detections were found
        detected_types = set()
        for detection in attack_detections:
            detected_types.add(detection.detection_type)
        
        expected_set = set(expected_detections)
        detected_set = detected_types.intersection(expected_set)
        missed_set = expected_set - detected_set
        
        # Calculate detection rate
        detection_rate = len(detected_set) / len(expected_set) if expected_set else 0.0
        
        result = {
            'attack_id': attack_id,
            'expected_detections': expected_detections,
            'detected_detections': list(detected_set),
            'missed_detections': list(missed_set),
            'detection_rate': detection_rate,
            'fully_detected': detection_rate == 1.0,
            'partially_detected': detection_rate > 0 and detection_rate < 1.0,
            'not_detected': detection_rate == 0.0
        }
        
        print(f"[BlueTeam Integration] Detection validation for {attack_id}:")
        print(f"[BlueTeam Integration] Expected: {expected_detections}")
        print(f"[BlueTeam Integration] Detected: {list(detected_set)}")
        print(f"[BlueTeam Integration] Missed: {list(missed_set)}")
        print(f"[BlueTeam Integration] Detection Rate: {detection_rate:.1%}")
        
        return result
    
    def get_purple_team_metrics(self) -> Dict[str, Any]:
        """
        Get current purple team metrics.
        
        Returns:
            Dict: Purple team metrics
        """
        return self.purple_team_metrics.copy()
    
    def generate_purple_team_report(
        self, 
        attack_id: str = None
    ) -> Dict[str, Any]:
        """
        Generate a comprehensive purple team report.
        
        Args:
            attack_id: Optional ID of a specific attack to report on
            
        Returns:
            Dict: Purple team report
        """
        if attack_id:
            # Generate report for specific attack
            return self._generate_attack_report(attack_id)
        else:
            # Generate overall report
            return self._generate_overall_report()
    
    def _update_metrics(
        self, 
        attack_id: str, 
        detected: bool, 
        confidence: float
    ):
        """Update purple team metrics based on detection results"""
        metrics = self.purple_team_metrics
        
        metrics['total_attacks'] += 1
        
        if detected:
            metrics['detected_attacks'] += 1
            # Update mean time to detect (simplified)
            # In a real implementation, we'd track actual detection times
            if metrics['mean_time_to_detect'] == 0:
                metrics['mean_time_to_detect'] = 1.0  # Default value
        else:
            metrics['false_negatives'] += 1
        
        # Update detection rate
        if metrics['total_attacks'] > 0:
            metrics['detection_rate'] = metrics['detected_attacks'] / metrics['total_attacks']
    
    def _generate_attack_report(self, attack_id: str) -> Dict[str, Any]:
        """Generate a report for a specific attack"""
        # Get all notifications for this attack
        attack_notifications = [
            n for n in self.red_team_notifications
            if n['attack_id'] == attack_id
        ]
        
        # Get all detection events for this attack
        attack_detections = [
            e for e in self.detection_events.values()
            if e.attack_id == attack_id
        ]
        
        # Calculate metrics for this attack
        detection_rate = len(attack_detections) / len(attack_notifications) if attack_notifications else 0.0
        
        return {
            'attack_id': attack_id,
            'red_team_actions': len(attack_notifications),
            'blue_team_detections': len(attack_detections),
            'detection_rate': detection_rate,
            'notifications': attack_notifications,
            'detections': [
                {
                    'event_id': e.event_id,
                    'detection_type': e.detection_type,
                    'timestamp': e.timestamp.isoformat(),
                    'severity': e.severity,
                    'confidence': e.confidence,
                    'details': e.details
                }
                for e in attack_detections
            ]
        }
    
    def _generate_overall_report(self) -> Dict[str, Any]:
        """Generate an overall purple team report"""
        return {
            'metrics': self.purple_team_metrics,
            'total_notifications': len(self.red_team_notifications),
            'total_detections': len(self.detection_events),
            'recent_attacks': self._get_recent_attacks()
        }
    
    def _get_recent_attacks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get information about recent attacks"""
        # Get unique attack IDs from notifications
        attack_ids = set(n['attack_id'] for n in self.red_team_notifications)
        
        recent_attacks = []
        for attack_id in list(attack_ids)[:limit]:
            attack_report = self._generate_attack_report(attack_id)
            recent_attacks.append(attack_report)
        
        return recent_attacks
    
    def start_purple_team_exercise(
        self, 
        exercise_name: str, 
        red_team_scope: Dict[str, Any], 
        blue_team_config: Dict[str, Any]
    ) -> str:
        """
        Start a new purple team exercise.
        
        Args:
            exercise_name: Name of the exercise
            red_team_scope: Scope for the red team
            blue_team_config: Configuration for the blue team
            
        Returns:
            str: Exercise ID
        """
        exercise_id = f"purple-exercise-{uuid.uuid4().hex[:12].upper()}"
        
        exercise = {
            'exercise_id': exercise_id,
            'exercise_name': exercise_name,
            'start_time': datetime.now(timezone.utc).isoformat(),
            'status': 'STARTED',
            'red_team_scope': red_team_scope,
            'blue_team_config': blue_team_config,
            'metrics': {
                'detection_rate': 0.0,
                'false_positives': 0,
                'false_negatives': 0
            }
        }
        
        print(f"[BlueTeam Integration] Purple team exercise started: {exercise_name}")
        print(f"[BlueTeam Integration] Exercise ID: {exercise_id}")
        
        return exercise_id
    
    def end_purple_team_exercise(
        self, 
        exercise_id: str
    ) -> Dict[str, Any]:
        """
        End a purple team exercise and generate final report.
        
        Args:
            exercise_id: ID of the exercise to end
            
        Returns:
            Dict: Final exercise report
        """
        end_time = datetime.now(timezone.utc)
        
        # In a real implementation, we'd look up the exercise and calculate final metrics
        report = {
            'exercise_id': exercise_id,
            'end_time': end_time.isoformat(),
            'status': 'COMPLETED',
            'final_metrics': self.purple_team_metrics.copy()
        }
        
        print(f"[BlueTeam Integration] Purple team exercise ended: {exercise_id}")
        
        return report
