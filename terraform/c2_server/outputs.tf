# Outputs for C2 Server Infrastructure

output "c2_server_ip" {
  description = "IP address of the C2 server"
  value       = digitalocean_droplet.c2_server.ipv4_address
}

output "c2_server_domain" {
  description = "Domain name of the C2 server"
  value       = var.c2_domain
}

output "c2_server_url" {
  description = "URL of the C2 server"
  value       = "https://${var.c2_domain}"
}

output "redirector_ips" {
  description = "IP addresses of redirector servers"
  value       = [for droplet in digitalocean_droplet.redirector : droplet.ipv4_address]
}

output "redirector_domains" {
  description = "Domain names of redirector servers"
  value       = [for i in range(var.c2_redirector_count) : "redirector${i + 1}.${var.c2_domain}"]
}

output "c2_auth_token" {
  description = "Authentication token for C2 server"
  value       = random_password.c2_auth_token.result
  sensitive   = true
}

# Generate random authentication token
resource "random_password" "c2_auth_token" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}
