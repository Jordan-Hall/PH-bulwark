terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Latest Ubuntu 22.04 LTS (Canonical) in the selected region.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "aegis" {
  name_prefix = "ph-bulwark-"
  description = "PH Bulwark server: gRPC + SSH"

  ingress {
    description = "Aegis gRPC"
    from_port   = var.aegis_port
    to_port     = var.aegis_port
    protocol    = "tcp"
    cidr_blocks = [var.app_cidr]
  }
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }
  egress {
    description = "all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "ph-bulwark-${var.region}" }
}

resource "aws_instance" "aegis" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.aegis.id]

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    aegis_image = var.aegis_image
    aegis_port  = var.aegis_port
  })

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  tags = { Name = "ph-bulwark-server-${var.region}" }
}
