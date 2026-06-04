# Aegis cluster — deploy as code (Ansible)

Give it the IPs of your Ubuntu hosts; it installs Docker and runs `aegis-server`
on each — one **LB/coordinator** + N **workers** that seed off the LB. **Scale out**
by adding worker IPs and re-running (idempotent).

## Prerequisites
1. An `aegis-server` image in a registry your hosts can pull. Build + push once
   (from the repo root) — use the cluster feature build:
   ```sh
   docker build -f deploy/docker/Dockerfile --build-arg FEATURES=gossip,quorum \
       -t <registry>/aegis-server:latest .
   docker push <registry>/aegis-server:latest
   ```
2. Ansible + the required collections:
   ```sh
   ansible-galaxy collection install -r deploy/ansible/requirements.yml
   ```
3. SSH access (key) to each host as a sudo-capable user.

## Deploy
```sh
cp deploy/ansible/inventory.example.ini deploy/ansible/inventory.ini
# edit inventory.ini: [lb] + [workers] IPs, aegis_image, aegis_cluster_id, (opt) DSN
ansible-playbook -i deploy/ansible/inventory.ini deploy/ansible/site.yml
```

## Scale out
Add the new host IP under `[workers]` in `inventory.ini` and re-run the **same**
command. New workers seed off the LB via `AEGIS_CLUSTER_SEEDS`.

## What it sets per node
`AEGIS_NODE_ID` (the host), `AEGIS_CLUSTER_ID`, `AEGIS_CLUSTER_ADDRESS`
(`host:port` advertised to peers), and — on workers — `AEGIS_CLUSTER_SEEDS` = the
LB's address; optional `AEGIS_QUORUM_DSN` for the shared Postgres lease store. See
`docs/deployment.md` §2 for the full contract.

## Honest status
This automates the **deploy + scale workflow** on the verified deployment unit (the
Docker image) using real, env-configured cluster settings (`ClusterConfig::from_env`).
The multi-node gossip/quorum **runtime** — cross-node work distribution and the
Postgres lease store that prevents split-brain — is feature-gated (`gossip,quorum`)
and **not yet validated end-to-end on real hosts**. Each node serves the gRPC API
today; provision a shared Postgres and validate failover before relying on quorum.
