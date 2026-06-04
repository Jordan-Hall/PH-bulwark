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

variable "wg_enabled" {
  description = "Open the WireGuard UDP port for the route-to-London VPN mode (deploy/wireguard/setup-london.sh). WireGuard ignores unauthenticated packets, so an open port is low-risk."
  type        = bool
  default     = false
}

variable "wg_port" {
  description = "WireGuard UDP listen port."
  type        = number
  default     = 51820
}

variable "ssm_instance_profile" {
  description = <<-EOT
    Name of an EXISTING IAM instance profile (with AmazonSSMManagedInstanceCore) to
    attach, enabling CI deploys via AWS SSM with NO inbound SSH (see docs/release.md
    §5). Empty = no profile (SSH-only). Created out-of-band: the scoped deploy user
    can't create IAM roles, so it's a one-time admin step.
  EOT
  type        = string
  default     = ""
}

variable "build_on_instance" {
  description = "Build the image ON the instance from source (no registry needed). Slower first boot (~10 min Rust build); recommend instance_type >= t3.medium so it doesn't OOM (a swapfile is also added). When false, pull var.aegis_image."
  type        = bool
  default     = false
}

variable "repo_url" {
  description = "Git repo to clone + build when build_on_instance = true (must be reachable from the instance; public for an unauthenticated clone)."
  type        = string
  default     = "https://github.com/Jordan-Hall/child-safety.git"
}
