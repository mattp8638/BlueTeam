# Variables for C2 Server Infrastructure

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "aws_access_key" {
  description = "AWS access key"
  type        = string
  sensitive   = true
  default     = ""
}

variable "aws_secret_key" {
  description = "AWS secret key"
  type        = string
  sensitive   = true
  default     = ""
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
