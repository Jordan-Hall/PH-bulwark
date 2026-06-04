variable "region" {
  description = <<-EOT
    AWS region = the country the server runs in. Clients pick a country, so deploy
    one per country (see README — terraform workspaces). Choices:
      us-east-1    N. Virginia, US   (RECOMMENDED FOR TESTING: a US egress reaches
      us-east-2    Ohio, US           adult test sites WITHOUT the UK age-
      us-west-2    Oregon, US         verification gate, so you can verify the
                                      filter blocks them — tunnel via the SSH SOCKS
                                      tip in the README)
      eu-west-2    London, UK        (UK-hosted; note UK adult sites now demand age
                                      verification, which gets in the way of testing
                                      from a UK egress)
      eu-central-1 Frankfurt, DE
  EOT
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 size. t3.small ~2 GB RAM, ~US$15/mo on-demand — fits a $20-30 budget. t3.micro (~$7.5/mo, 1 GB) is cheaper but tight."
  type        = string
  default     = "t3.small"
}

variable "key_name" {
  description = "Name of an EXISTING EC2 key pair in this region (for SSH)."
  type        = string
}

variable "ssh_cidr" {
  description = "CIDR allowed to SSH (set to YOUR_IP/32, not the default open)."
  type        = string
  default     = "0.0.0.0/0"
}

variable "app_cidr" {
  description = "CIDR allowed to reach the Aegis gRPC port."
  type        = string
  default     = "0.0.0.0/0"
}

variable "aegis_image" {
  description = "Container image to run (build from deploy/docker/Dockerfile + push to a registry your instance can pull)."
  type        = string
  default     = "ghcr.io/your-org/aegis-server:latest"
}

variable "aegis_port" {
  description = "gRPC port the server listens on / the SG opens."
  type        = number
  default     = 8443
}
