# C2 Server Infrastructure
# Deploys a command and control server for AI-RedTeaming operations

terraform {
  required_version = ">= 1.0.0"
  
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
    
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 3.0"
    }
  }
}

# Configure providers
provider "digitalocean" {
  token = var.do_token
}

provider "aws" {
  region = var.aws_region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# Variables
variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "aws_access_key" {
  description = "AWS access key"
  type        = string
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS secret key"
  type        = string
  sensitive   = true
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "cloudflare_api_token" {
  description = "Cloudflare API token"
  type        = string
  sensitive   = true
}

variable "c2_domain" {
  description = "Domain for C2 server"
  type        = string
  default     = "c2.example.com"
}

variable "c2_server_name" {
  description = "Name for C2 server"
  type        = string
  default     = "redteam-c2"
}

variable "c2_server_size" {
  description = "Size of C2 server droplet"
  type        = string
  default     = "s-2vcpu-2gb"
}

variable "c2_server_image" {
  description = "Image for C2 server"
  type        = string
  default     = "ubuntu-22-04-x64"
}

variable "c2_redirector_count" {
  description = "Number of redirector servers"
  type        = number
  default     = 2
}

variable "c2_redirector_size" {
  description = "Size of redirector droplets"
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "ssh_public_key" {
  description = "SSH public key for server access"
  type        = string
}

# Create C2 server on DigitalOcean
resource "digitalocean_droplet" "c2_server" {
  name      = var.c2_server_name
  region    = "nyc3"
  size      = var.c2_server_size
  image     = var.c2_server_image
  ssh_keys  = [var.ssh_public_key]
  
  tags = ["redteam", "c2", "server"]
  
  provisioner "remote-exec" {
    inline = [
      "# Update system",
      "apt-get update -y",
      "apt-get upgrade -y",
      
      "# Install dependencies",
      "apt-get install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx",
      
      "# Create redteam user",
      "useradd -m -s /bin/bash redteam",
      "usermod -aG sudo redteam",
      
      "# Setup Python virtual environment",
      "mkdir -p /opt/redteam",
      "python3 -m venv /opt/redteam/venv",
      ". /opt/redteam/venv/bin/activate && pip install aiohttp requests",
      
      "# Copy C2 server files",
      "mkdir -p /opt/redteam/c2_server",
      
      "# Setup systemd service",
      "cat > /etc/systemd/system/redteam-c2.service << 'EOL'",
      "[Unit]",
      "Description=AI-RedTeaming C2 Server",
      "After=network.target",
      "",
      "[Service]",
      "User=redteam",
      "WorkingDirectory=/opt/redteam/c2_server",
      "ExecStart=/opt/redteam/venv/bin/python /opt/redteam/c2_server/main.py",
      "Restart=always",
      "RestartSec=5",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOL",
      
      "# Enable and start service",
      "systemctl daemon-reload",
      "systemctl enable redteam-c2",
      "systemctl start redteam-c2",
      
      "# Setup nginx reverse proxy",
      "cat > /etc/nginx/sites-available/redteam-c2 << 'EOL'",
      "server {",
      "    listen 80;",
      "    server_name ${var.c2_domain};",
      "    ",
      "    location / {",
      "        proxy_pass http://127.0.0.1:8080;",
      "        proxy_set_header Host $host;",
      "        proxy_set_header X-Real-IP $remote_addr;",
      "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
      "        proxy_set_header X-Forwarded-Proto $scheme;",
      "    }",
      "}",
      "EOL",
      
      "ln -sf /etc/nginx/sites-available/redteam-c2 /etc/nginx/sites-enabled/",
      "nginx -t && systemctl restart nginx",
      
      "# Setup SSL with Let's Encrypt",
      "certbot --nginx -d ${var.c2_domain} --non-interactive --agree-tos -m admin@${var.c2_domain}",
    ]
  }
  
  connection {
    type        = "ssh"
    user        = "root"
    private_key = file("~/.ssh/id_rsa")
    timeout     = "2m"
  }
}

# Create redirector servers
resource "digitalocean_droplet" "redirector" {
  count    = var.c2_redirector_count
  name     = "${var.c2_server_name}-redirector-${count.index + 1}"
  region   = "nyc3"
  size     = var.c2_redirector_size
  image    = var.c2_server_image
  ssh_keys = [var.ssh_public_key]
  
  tags = ["redteam", "c2", "redirector"]
  
  provisioner "remote-exec" {
    inline = [
      "# Update system",
      "apt-get update -y",
      "apt-get upgrade -y",
      
      "# Install nginx",
      "apt-get install -y nginx",
      
      "# Configure nginx as reverse proxy to C2 server",
      "cat > /etc/nginx/sites-available/redirector << 'EOL'",
      "server {",
      "    listen 80;",
      "    server_name _;",
      "    ",
      "    location / {",
      "        proxy_pass http://${digitalocean_droplet.c2_server.ipv4_address}:8080;",
      "        proxy_set_header Host $host;",
      "        proxy_set_header X-Real-IP $remote_addr;",
      "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
      "        proxy_set_header X-Forwarded-Proto $scheme;",
      "    }",
      "}",
      "EOL",
      
      "ln -sf /etc/nginx/sites-available/redirector /etc/nginx/sites-enabled/",
      "rm -f /etc/nginx/sites-enabled/default",
      "nginx -t && systemctl restart nginx",
    ]
  }
  
  connection {
    type        = "ssh"
    user        = "root"
    private_key = file("~/.ssh/id_rsa")
    timeout     = "2m"
  }
}

# Create DNS records for C2 server
resource "cloudflare_record" "c2_server_a" {
  zone_id = data.cloudflare_zone.domain.id
  name    = var.c2_domain
  value   = digitalocean_droplet.c2_server.ipv4_address
  type    = "A"
  ttl     = 300
  proxied = true
}

# Create DNS records for redirectors
resource "cloudflare_record" "redirector_a" {
  count   = var.c2_redirector_count
  zone_id = data.cloudflare_zone.domain.id
  name    = "redirector${count.index + 1}.${var.c2_domain}"
  value   = digitalocean_droplet.redirector[count.index].ipv4_address
  type    = "A"
  ttl     = 300
  proxied = true
}

# Get Cloudflare zone ID
data "cloudflare_zone" "domain" {
  name = var.c2_domain
}

# Outputs
output "c2_server_ip" {
  value = digitalocean_droplet.c2_server.ipv4_address
}

output "c2_server_domain" {
  value = var.c2_domain
}

output "redirector_ips" {
  value = [for droplet in digitalocean_droplet.redirector : droplet.ipv4_address]
}

output "redirector_domains" {
  value = [for i in range(var.c2_redirector_count) : "redirector${i + 1}.${var.c2_domain}"]
}
