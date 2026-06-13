# research.predatorhunters.co.uk — deploy

The Predator Hunters Research site (Dioxus 0.8 web/wasm, `apps/research`) ships as
a small nginx image, built in CI and run on the existing EC2 box via AWS SSM — the
same no-SSH pattern as `deploy.yml` for the server.

## Pipeline

`.github/workflows/research-site.yml` (on push to `master` touching `apps/research/**`,
`deploy/research/**`, or `branding/**`, or via **Run workflow**):

1. **build-image** — `docker build -f deploy/research/Dockerfile .` compiles the wasm
   bundle with `dx build --platform web --release` and bakes it into `nginx:alpine`,
   smoke-tests it, and pushes `ghcr.io/jordan-hall/research-site:{sha,latest}`.
2. **deploy** — SSM `docker pull` + `docker run -d --name research-site -p 80:80`
   on the box (Environment `production`). Reuses the deploy.yml AWS secrets/vars.

## One-time prerequisites

1. **Cloudflare DNS** — ✅ **done**: a **proxied** (orange-cloud) `A` record
   `research` → `35.179.110.106` exists. Cloudflare terminates TLS at the edge.
2. **Cloudflare SSL/TLS mode** — must be **Flexible** for the edge to reach this
   plain-HTTP origin on `:80`. (Or **Full** — then the origin needs its own TLS;
   the nginx config here is HTTP-only, so Flexible is the matching default.)
3. **Security group** — allow inbound **:80** (default `RESEARCH_PORT`), ideally
   restricted to Cloudflare IP ranges. ⚠️ The scoped deploy IAM is `ssm:SendCommand`
   only and cannot edit the SG — do this via the console or `deploy/aws` terraform.
4. **GitHub repo var** (optional) — `RESEARCH_PORT` if not 80.

Once the SSL mode + SG are set, a merge to `master` (or **Run workflow**) deploys.

## Notes / to validate on first CI run

- `dx` (dioxus-cli) is pinned to `0.8.0-alpha.0`; if the alpha CLI install or the
  `target/dx/**/release/web/public` output path differs, adjust the Dockerfile.
- This is a static origin sharing the box with `bulwark-server` (:8443). It uses a
  separate container, port, and image — it does not touch the server deploy.
