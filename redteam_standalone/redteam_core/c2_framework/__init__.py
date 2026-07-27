"""
C2 Framework

Command and Control infrastructure for AI-RedTeaming operations.
"""

from .c2_server import C2Server
from .c2_client import C2Client
from .payload_generator import PayloadGenerator
from .communication_protocols import HTTPProtocol, HTTPSProtocol, DNSProtocol, WebSocketProtocol

__all__ = [
    'C2Server',
    'C2Client', 
    'PayloadGenerator',
    'HTTPProtocol',
    'HTTPSProtocol', 
    'DNSProtocol',
    'WebSocketProtocol'
]
