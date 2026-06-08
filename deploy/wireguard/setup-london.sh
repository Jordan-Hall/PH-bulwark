#!/usr/bin/env bash
# PH Bulwark — WireGuard server setup for the route-to-London VPN mode.
#
# Stands up a WireGuard endpoint on the London EC2 so child devices can tunnel
# their traffic to it (data residency + the "PH Bulwark Cloud — UK" picker option).
# This is the TRANSPORT half (boringtun on the device speaks the same protocol).
# The AI MITM filter (bulwark-net proxy) running ON the tunnelled traffic is a
# separate follow-up; this script gets a working, testable tunnel first.
#
# RUN IT ON THE SERVER (it makes a privileged, world-reachable change — do it with
# your own authority, not from an agent):
#   ssh -i ~/.ssh/ph-bulwark-london.pem ubuntu@ec2-35-179-110-106.eu-west-2.compute.amazonaws.com 'sudo bash -s' < deploy/wireguard/setup-london.sh
# It prints a client config at the end — import it into the WireGuard app to verify
# London routing works, before we wire the in-app boringtun client.
#
# You must ALSO open UDP 51820 on the security group (see deploy/aws Terraform
# `wg_port` rule, or: aws ec2 authorize-security-group-ingress --group-id <sg> \
#   --protocol udp --port 51820 --cidr 0.0.0.0/0 --region eu-west-2).
set -euo pipefail

PORT="${WG_PORT:-51820}"
ENDPOINT_HOST="${WG_ENDPOINT:-35.179.110.106}"
WG_DIR=/etc/wireguard
export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get install -y wireguard

DEV="$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')"
umask 077
mkdir -p "$WG_DIR"

# Server + one test-client keypair (idempotent — reuse if present).
[ -f "$WG_DIR/server.key" ] || wg genkey > "$WG_DIR/server.key"
wg pubkey < "$WG_DIR/server.key" > "$WG_DIR/server.pub"
[ -f "$WG_DIR/client.key" ] || wg genkey > "$WG_DIR/client.key"
wg pubkey < "$WG_DIR/client.key" > "$WG_DIR/client.pub"

SPRIV="$(cat "$WG_DIR/server.key")"; SPUB="$(cat "$WG_DIR/server.pub")"
CPRIV="$(cat "$WG_DIR/client.key")"; CPUB="$(cat "$WG_DIR/client.pub")"

cat > "$WG_DIR/wg0.conf" <<EOF
[Interface]
Address = 10.8.0.1/24
ListenPort = $PORT
PrivateKey = $SPRIV
PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEV -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEV -j MASQUERADE

[Peer]
PublicKey = $CPUB
AllowedIPs = 10.8.0.2/32
EOF

sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wg.conf
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

cat > "$WG_DIR/client-test.conf" <<EOF
[Interface]
PrivateKey = $CPRIV
Address = 10.8.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = $SPUB
Endpoint = $ENDPOINT_HOST:$PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

echo "=================== WireGuard up. Test client config: ==================="
cat "$WG_DIR/client-test.conf"
echo "========================================================================="
wg show
