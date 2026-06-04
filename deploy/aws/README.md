# Deploy PH Bulwark on AWS (single EC2, multi-country)

One small EC2 per country, provisioned with Terraform. You run it with **your own**
AWS credentials — nothing here touches your account. The server auto-starts on boot
(cloud-init installs Docker + runs the container).

## Prerequisites
- AWS credentials configured locally (`aws configure`, or `AWS_ACCESS_KEY_ID` /
  `AWS_SECRET_ACCESS_KEY` env), and Terraform ≥ 1.3.
- An **EC2 key pair** that already exists *in each region* you deploy to (for SSH).
- The server **image** pushed to a registry your instance can pull (public GHCR is
  easiest): `docker build -f deploy/docker/Dockerfile -t <registry>/aegis-server:latest . && docker push …`

## Deploy one country
```sh
cd deploy/aws
terraform init
terraform apply \
  -var region=eu-west-2 \           # London (see variables.tf for the country list)
  -var key_name=my-keypair \
  -var ssh_cidr=$(curl -s ifconfig.me)/32 \   # lock SSH to your IP
  -var aegis_image=ghcr.io/your-org/aegis-server:latest
# -> outputs the public endpoint; set it in the client (self-hosted, or as a
#    PH Bulwark Cloud regional endpoint).
```

### Testing tip — reach adult test sites without the UK age gate
To verify PH Bulwark actually **blocks** adult content you need that content to load
in the first place. UK adult sites now demand **age verification** (sign-in / ID),
which gets in the way. Deploy in a **US region** and route your test browser through
the instance so it egresses from the US (no age gate), while the on-device filter
does its job:
```sh
ssh -D 1080 -N ubuntu@<ec2-public-dns>     # SOCKS5 proxy on localhost:1080
# point your test browser's SOCKS proxy at localhost:1080 → US egress
```
This uses the EC2 you already deployed — no extra cost.

## Multi-country (let users pick) — one workspace per region
Each workspace keeps its own state, so you get one instance per country:
```sh
terraform workspace new london && terraform apply -var region=eu-west-2 -var key_name=… …
terraform workspace new us-east && terraform apply -var region=us-east-1 -var key_name=… …
# list endpoints later: terraform workspace select london && terraform output endpoint
```
Wire each region's endpoint into the client's country picker (PH Bulwark Cloud —
London / US / …).

## Cost (keep it ~$20-30/month)
On-demand, approx (us/eu), incl. a 20 GB gp3 disk:

| Instance | RAM | ~ / month | Notes |
|---|---|---|---|
| `t3.micro` | 1 GB | **~$9** | Cheapest; fine for light testing. Run **two countries ≈ $18**. |
| `t3.small` | 2 GB | **~$17** | Default; comfortable headroom. One country fits the budget; two ≈ $34 (over). |

Guidance for a **$20-30/mo** cap: either **one `t3.small`** region, or **two
`t3.micro`** regions (`-var instance_type=t3.micro`). **Stop instances when idle**
(`aws ec2 stop-instances`) to pay only for storage. Tear everything down with
`terraform destroy`.

## Honest caveats
- **Single EC2 = single point of failure** — fine for testing; for real scale use the
  multi-node Ansible cluster (`deploy/ansible/`).
- **Plaintext `http`** by default (no TLS). Put it behind a TLS terminator (Caddy /
  ALB / nginx) or supply server certs before non-test use.
- The security group defaults to `0.0.0.0/0` — **set `ssh_cidr`/`app_cidr`** to real
  ranges.
- The image must be pullable by the instance (public registry, or configure auth).
