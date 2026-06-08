output "public_ip" {
  description = "The server's public IP."
  value       = aws_instance.bulwark.public_ip
}

output "public_dns" {
  description = "The server's public DNS name."
  value       = aws_instance.bulwark.public_dns
}

output "endpoint" {
  description = "Set this as the self-hosted server URL in the client (or as a PH Bulwark Cloud regional endpoint). Plaintext until you add TLS — see README."
  value       = "http://${aws_instance.bulwark.public_dns}:${var.bulwark_port}"
}

output "region" {
  description = "The region/country this server runs in."
  value       = var.region
}
