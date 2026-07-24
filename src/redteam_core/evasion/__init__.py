"""
Evasion Framework

Anti-detection and evasion techniques for AI-RedTeaming operations.
"""

from .sandbox_detection import SandboxDetector
from .av_evasion import AVEvader
from .memory_evader import MemoryEvader
from .network_evader import NetworkEvader
from .obfuscator import CodeObfuscator
from .polymorphic import PolymorphicEngine

__all__ = [
    'SandboxDetector',
    'AVEvader', 
    'MemoryEvader',
    'NetworkEvader',
    'CodeObfuscator',
    'PolymorphicEngine'
]
