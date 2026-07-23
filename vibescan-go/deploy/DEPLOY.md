# VibeScan Deployment Runbook (AWS)

Start-to-finish deploy of the current MVP on this stack:

| Piece | What |
|-------|------|
| **Web host** | AWS **EC2 t3.micro**, image **pulled** from **Amazon ECR** (built on your laptop — the 1 GB box cannot compile it) |
| **Database** | **MongoDB Atlas M0** (free), **AWS us-east-1** (same region as EC2) |
| **Screenshots** | **Amazon S3** (private) served via **CloudFront** |
| **TLS / reverse proxy** | **Caddy** (auto-HTTPS from Let's Encrypt) in front of the Go app |
| **Scanner** | Separate **scanner host** running the **Go agent** (`Dockerfile.agent`: nmap + Chromium) |

One process serves everything on the web host: **ingest API + v2 read APIs + embedded React UI** (same origin — no CORS in production).

```
 Scanner host                             EC2 t3.micro              Atlas M0 (AWS)
 ┌────────────┐  1. scan → the internet   ┌────────────────┐       ┌────────┐
 │  Go agent  │ ────────────────────────▶ │ HTTP services  │       │ Mongo  │
 │  nmap+CDP  │                           │ Caddy → vibescan│──────▶└────────┘
 │            │ ─2. submit (HTTPS)───────▶│ UI+API+ingest  │──────▶ S3 + CloudFront
 └────────────┘                           └───────┬────────┘
   browser ─── https://YOUR_DOMAIN ───────────────┘
```

> **Repo layout this runbook assumes:** you are working from the monorepo root
> (`vibescan_rework/`), with `vibescan-go/` and `vibescan-ui/` as siblings. The
> multi-stage app `Dockerfile` builds the UI, embeds it, and produces the
> runtime image. Paths below are relative to that root unless noted.

---

## 0. Pre-flight

**Values to gather** (substitute throughout):

| Placeholder | What | Example |
|---|---|---|
| `ACCOUNT_ID` | your 12-digit AWS account id | `123456789012` |
| `REGION` | east-coast region (match EC2 + Atlas + S3) | `us-east-1` |
| `YOUR_DOMAIN` | site hostname | `vibescan.example.com` |
| `YOUR_IP` | your admin IP (for SSH allow) | `203.0.113.7` |

**On your laptop:**

- AWS CLI (`brew install awscli`, then `aws configure` with an admin/IAM user)
- Docker Desktop (with buildx — included in current Docker Desktop)

**Account notes:** the **12-month EC2 free tier** applies only to newer accounts; after that a t3.micro is roughly $7–8/mo. AWS bills **all public IPv4 (~$3.60/mo)** even while attached, so the Elastic IP is not free either. Atlas M0 is free; S3 + CloudFront is effectively free at low traffic (CloudFront’s free-tier egress for new accounts is large).

**Optional alternative hosts:** if the web host has ≥2 GB RAM you can **build on the server** with `docker-compose.yml` instead of ECR (see §4b). This runbook’s default path is the small t3.micro + registry flow.

---

## 1. Create the EC2 web host

```bash
export AWS_DEFAULT_REGION=us-east-1

# SSH key pair (saves a private key locally)
aws ec2 create-key-pair --key-name vibescan \
  --query KeyMaterial --output text > ~/.ssh/vibescan.pem && chmod 400 ~/.ssh/vibescan.pem

# Security group: 80/443 from anywhere, 22 from your IP only
SG=$(aws ec2 create-security-group --group-name vibescan-web \
  --description "vibescan web" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id $SG --protocol tcp --port 80  --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $SG --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $SG --protocol tcp --port 22  --cidr YOUR_IP/32

# IAM instance role so the box can pull from ECR (no keys on the host)
aws iam create-role --role-name vibescan-ec2 --assume-role-policy-document \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name vibescan-ec2 \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
aws iam create-instance-profile --instance-profile-name vibescan-ec2
aws iam add-role-to-instance-profile --instance-profile-name vibescan-ec2 --role-name vibescan-ec2

# Latest Ubuntu 24.04 AMI (via SSM, so it's always current)
AMI=$(aws ssm get-parameter \
  --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
  --query Parameter.Value --output text)

# Launch t3.micro (30 GB gp3)
# Note: instance profiles can take ~10–30s to become usable after create/attach.
sleep 15
IID=$(aws ec2 run-instances --image-id $AMI --instance-type t3.micro \
  --key-name vibescan --security-group-ids $SG \
  --iam-instance-profile Name=vibescan-ec2 \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=vibescan-web}]' \
  --query 'Instances[0].InstanceId' --output text)

# Wait until the instance is running and status checks pass before SSHing
aws ec2 wait instance-running --instance-ids $IID
aws ec2 wait instance-status-ok --instance-ids $IID

# Static Elastic IP
ALLOC=$(aws ec2 allocate-address --query AllocationId --output text)
aws ec2 associate-address --instance-id $IID --allocation-id $ALLOC
EIP=$(aws ec2 describe-addresses --allocation-ids $ALLOC --query 'Addresses[0].PublicIp' --output text)
echo "EC2 public IP: $EIP"
```

**Point DNS:** create an **A record** `YOUR_DOMAIN → $EIP`. If it’s behind Cloudflare’s proxy, set it **DNS-only (grey cloud)** so Caddy can complete the ACME HTTP-01 challenge. Verify:

```bash
dig +short YOUR_DOMAIN   # must print $EIP
```

**Install Docker on the host:**

```bash
ssh -i ~/.ssh/vibescan.pem ubuntu@$EIP
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && exit        # re-login for the group
```

---

## 2. MongoDB Atlas (M0)

1. **[cloud.mongodb.com](https://cloud.mongodb.com)** → Create → **M0 Free**, provider **AWS**, region **`us-east-1` (N. Virginia)** — same region as the EC2 host.
2. **Database Access** → add a user (password auth). Save the password.
3. **Network Access** → allow the Elastic IP `EIP` (or `0.0.0.0/0` only while bringing the stack up).
4. **Connect → Drivers** → copy a URI like:

   ```
   mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
   ```

   URL-encode special characters in the password (`@` → `%40`, `#` → `%23`, etc.). The `vibescan` database is created on first write (`MONGO_DB` / `MONGO_COLLECTION` below).

> **M0 caveats:** no automated backups; the cluster **auto-pauses after ~60 days idle** (resume in the Atlas UI; the app reconnects on wake). Set up `mongodump` backups (§Ops) and plan a move to Atlas Flex/M10 as data or backup needs grow.

---

## 3. Amazon S3 + CloudFront (screenshots)

Private S3 bucket for storage; CloudFront serves objects publicly (CDN cache + large free egress tier, so S3 egress stays low). The collector **uploads** with `s3:PutObject`; browsers **read** via CloudFront only.

```bash
export AWS_DEFAULT_REGION=us-east-1

# Bucket names are globally unique — pick one that is free (example may already exist).
BUCKET=vibescan-captures-$ACCOUNT_ID   # or any unique name
aws s3api create-bucket --bucket "$BUCKET" --region us-east-1

# IAM user the collector uses to upload (write-only to this bucket)
aws iam create-user --user-name vibescan-s3
aws iam put-user-policy --user-name vibescan-s3 --policy-name put-captures \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\"],\"Resource\":\"arn:aws:s3:::${BUCKET}/*\"}]}"
aws iam create-access-key --user-name vibescan-s3
# → save AccessKeyId / SecretAccessKey as S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY
```

**CloudFront (console is easiest):**

1. Create a distribution → **Origin** = this S3 bucket.
2. **Origin access** = *Origin access control (OAC)*; apply the bucket policy the console generates (lets only CloudFront read the bucket).
3. Optionally add `img.YOUR_DOMAIN` as an alternate domain name with an ACM cert in `us-east-1`.
4. The distribution domain (`dxxxx.cloudfront.net` or `img.YOUR_DOMAIN`) is your **`S3_PUBLIC_URL`**.

The app stores captures as `r2:<object-key>` in Mongo and resolves images as:

```
{S3_PUBLIC_URL}/{key}     e.g. https://dxxxx.cloudfront.net/1/2/1.2.3.4-80.png
```

Config values used by the collector (see `.env.example`; both `S3_*` and legacy `R2_*` names work):

| Variable | Example |
|----------|---------|
| `S3_ENABLED` | `1` |
| `S3_BUCKET_NAME` | `$BUCKET` |
| `S3_ENDPOINT_URL` | `https://s3.us-east-1.amazonaws.com` |
| `S3_REGION` | `us-east-1` (required for SigV4 on AWS) |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | from the IAM user above |
| `S3_PUBLIC_URL` | `https://dxxxx.cloudfront.net` (no trailing slash) |
| `S3_FALLBACK_TO_MONGO` | `1` — keep base64 in Mongo if an upload fails |

> Captured screenshots are **public data** once served via CloudFront, and can contain personal/sensitive/NSFW content. Treat them as public, keep an opt-out/removal path, and consider content filtering (see §7).

---

## 4. Build the image and push to ECR (laptop)

The app image is multi-stage: **Node builds `vibescan-ui` → embeds into the Go binary → slim Alpine runtime** (~60 MB). Binaries in the image:

| Path | Role |
|------|------|
| `/usr/local/bin/vibescan` | collector + v2 APIs + embedded UI (default `ENTRYPOINT`) |
| `/usr/local/bin/migrate` | one-shot Mongo index creation + blacklist seed |

```bash
export AWS_DEFAULT_REGION=us-east-1

# one-time: create the ECR repository
aws ecr create-repository --repository-name vibescan --region us-east-1

# build linux/amd64 (Apple Silicon is arm64) → login to ECR → push an immutable tag.
# build-push.sh creates the buildx container-builder on first run.
cd vibescan-go/deploy
REGION=us-east-1 ACCOUNT_ID=ACCOUNT_ID ./build-push.sh
# → prints:  IMAGE=ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/vibescan:YYYYmmdd-HHMMSS
```

`build-push.sh` uses the **monorepo root** as Docker context (so it can copy both `vibescan-ui/` and `vibescan-go/`). Optional overrides: `TAG=…`, `REPO=vibescan`.

The EC2 host pulls with its **instance role** (attached in §1) — no AWS keys to copy onto the box.

### 4b. Alternative: build on a larger server

If the host has enough RAM (≥2 GB recommended), skip ECR and use `docker-compose.yml` from `deploy/` (builds from the monorepo root). Copy the whole monorepo (or at least `vibescan-go/` + `vibescan-ui/`), fill `.env` (no `IMAGE=` needed), then:

```bash
cd vibescan-go/deploy
docker compose build
docker compose run --rm --entrypoint migrate app
docker compose up -d
```

---

## 5. Configure & launch on the host

Ship **only** the `deploy/` folder for the registry flow (compose, Caddyfile, env, GeoIP DB — not the source tree):

```bash
# From the monorepo root on your laptop
scp -i ~/.ssh/vibescan.pem -r vibescan-go/deploy ubuntu@$EIP:~/deploy
```

SSH in and set up ECR auth via the **credential helper** (uses the instance role):

```bash
ssh -i ~/.ssh/vibescan.pem ubuntu@$EIP
sudo apt-get update && sudo apt-get install -y amazon-ecr-credential-helper
mkdir -p ~/.docker
cat > ~/.docker/config.json <<'EOF'
{ "credHelpers": { "ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com": "ecr-login" } }
EOF
```

Fill `.env` (`chmod 600`, never commit). Template is `deploy/.env.example`:

```bash
cd ~/deploy && cp .env.example .env && chmod 600 .env && nano .env
```

```ini
# Required for docker-compose.registry.yml — pin the tag from build-push.sh
IMAGE=ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/vibescan:YYYYmmdd-HHMMSS

DOMAIN=YOUR_DOMAIN
VIBESCAN_PUBLIC_URL=https://YOUR_DOMAIN

# Shared with every scanner agent (HMAC). Generate once and keep offline too.
VIBESCAN_SHARED_KEY=<openssl rand -hex 32>

MONGO_URI=mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
MONGO_DB=vibescan
MONGO_COLLECTION=results

S3_ENABLED=1
S3_BUCKET_NAME=vibescan-captures-ACCOUNT_ID
S3_ENDPOINT_URL=https://s3.us-east-1.amazonaws.com
S3_REGION=us-east-1
S3_ACCESS_KEY_ID=<vibescan-s3 access key>
S3_SECRET_ACCESS_KEY=<vibescan-s3 secret>
S3_PUBLIC_URL=https://dxxxxxxxxxxxxx.cloudfront.net    # or https://img.YOUR_DOMAIN
S3_FALLBACK_TO_MONGO=1

# Optional: verbose ingest logs
# VIBESCAN_DEBUG=1
```

**Local HTTP-only smoke test (optional):** set `DOMAIN=:80` and skip DNS/TLS while iterating on a throwaway box.

### GeoIP (world map)

The UI world map uses MaxMind **GeoLite2-City**. Put `GeoLite2-City.mmdb` in `~/deploy/` (a copy often ships next to the compose files if you scp’d the whole `deploy/` dir).

Obtain a free account and DB from [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) if you don’t already have the file.

**If you skip it, comment out the `GeoLite2-City.mmdb` volume line** in `docker-compose.registry.yml` (and `docker-compose.yml`). Otherwise Docker silently mounts an **empty directory** over the path and GeoIP returns nothing with no error — the map stays blank.

### Launch — migrate first, then serve

The app also creates indexes in the background on startup, but prepping schema before traffic is the right order. The image’s default entrypoint is `vibescan`; migrate is a separate binary:

```bash
C="docker compose -f docker-compose.registry.yml"
$C pull
$C run --rm --entrypoint migrate app      # create indexes + seed CIDR blacklist
$C up -d                                   # app + Caddy
$C logs -f caddy                           # wait for "certificate obtained successfully"
```

Compose files bound-log containers to **3 × 10 MB** (`json-file`) so a small disk cannot fill from logs alone.

**Disk buffer note:** if Mongo is unreachable, the collector spools submissions under `cache/server_buffer/` **inside** the container. That path is **not** volume-mounted by default — a restart drops unflushed buffer files. Acceptable for MVP; for durability add a named volume on that path later.

---

## 6. Smoke test

```bash
curl -sS https://YOUR_DOMAIN/api/healthz     # {"ok":true}
curl -sS https://YOUR_DOMAIN/api/health      # {"status":"ok","service":"vibescan-collector"}
curl -sS https://YOUR_DOMAIN/api/v2/stats    # totals: hosts 0, services 0 until agents submit
```

Open `https://YOUR_DOMAIN/` → the vibescan console loads (empty until the scanner runs).

Useful read endpoints (no auth yet):

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v2/gallery` | recent tiles |
| `GET /api/v2/search?q=` | filtered search |
| `GET /api/v2/stats?time_range=24` | windowed aggregates |
| `GET /api/v2/random-capture` | one landing tile |
| `GET /api/v2/services/{ip}/{port}` | service detail |
| `GET /api/v2/image/{ip}/{port}` | base64 capture or 302 → S3/CloudFront |

Ingest (agents only, HMAC-gated):

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/results` | signed gzip+base64 envelope |
| `GET /api/v1/blacklist` | enabled CIDRs (agents cache hourly) |

---

## 7. Scanner host (Go agent)

Run the agent on a dedicated machine with enough CPU/RAM for **nmap + headless Chromium**. Prefer a host whose egress IP you are comfortable exposing to the public internet (and to any target that logs clients).

**OPSEC / reputation:**

- The scanner’s **egress IP** is what targets (and reputation lists) see. Personal or residential egress can accumulate blocks/CAPTCHAs for normal browsing on that network.
- Honor opt-outs **centrally** via the server-side CIDR blacklist (below); don’t rely on being easy to contact via the scan source.
- To keep personal egress off the scan path, tunnel agent traffic (e.g. WireGuard) through a VPS you control — agent config is unchanged.
- Set `VIBESCAN_NO_REPORT=1` so the collector stores `submitted_by=0.0.0.0` and marks `anon=true` (also redacted on the public service-detail API). This does **not** hide the scan source from targets.

**Isolation:** the agent renders **hostile/unknown pages** in Chromium. Keep it containerized (it is), patch the host, and preferably isolate the scanner from trusted LAN devices (separate VLAN / host).

### Run the Go agent

Image: `vibescan-go/Dockerfile.agent` (nmap + Chromium + fonts + static `agent` binary). Compose builds it on the scanner host (not pulled from ECR).

Copy **`vibescan-go/`** to the scanner host (only this tree is required for the agent build), then:

```bash
cd vibescan-go/deploy
cp agent.env.example agent.env && nano agent.env
# set VIBESCAN_SERVER_URL + VIBESCAN_SHARED_KEY (must match the collector .env)

docker compose -f docker-compose.agent.yml up -d --build
docker compose -f docker-compose.agent.yml logs -f
# expect lines like:  submitted N hosts → map[stored:… buffered:…]
```

Key `agent.env` values (see `agent.env.example` for the full set):

```ini
VIBESCAN_SERVER_URL=https://YOUR_DOMAIN     # collector base URL, no trailing path
VIBESCAN_SHARED_KEY=<EXACT same value as the collector .env>

VIBESCAN_PORTS=80,443,8000,8080,8443        # web HTTP + HTTPS
VIBESCAN_NMAP_OPTIONS=-n -T2                # polite; code default is -T3 if unset
VIBESCAN_RDAP=1                             # network owner via RDAP (cached)
VIBESCAN_SCAN_THREADS=4                     # concurrent host record builds
VIBESCAN_BATCH_SIZE=10                      # random IPs per nmap batch
VIBESCAN_BROWSER_CONCURRENCY=2              # concurrent Chromium captures
VIBESCAN_CAPTURE_DELAY=2.0                  # seconds for the page to settle
VIBESCAN_CAPTURE_HTTP=1                     # 0 = banners only, no screenshots

# Redact submitter IP in Mongo + public APIs (recommended on personal egress)
VIBESCAN_NO_REPORT=1
```

Compose grants `NET_RAW` / `NET_ADMIN` for nmap and `shm_size: 1gb` for Chromium. If nmap complains about privileges, set `privileged: true` on the service in `docker-compose.agent.yml`.

**RDAP / WHOIS:** the agent looks up network ownership via `rdap.org` (format
`NETNAME - Org`, cached per /24). Disable with `VIBESCAN_RDAP=0`. PTR (reverse
DNS) is still attempted. Captures, banners, status, cert CN, pHash, and DOM hash
are produced.

**Legacy Python agent:** `vibescan_v2/client_agent.py` still speaks the same v1 wire protocol and shared key if you need a temporary fallback. Note: the Python collector may still store the real submitter IP even when `no_report` is set; this Go collector redacts it.

### Operating norms

Connecting to public HTTP is generally lawful in many jurisdictions when done carefully; these keep it clean and courteous:

- **Honor opt-outs centrally:** the collector’s CIDR blacklist drives all agents (`GET /api/v1/blacklist`). Add a complainer’s range and every agent skips it.
- **Moderate content:** captures can include sensitive/NSFW/personal data — filter where you can, and honor removal requests.
- **Be polite:** `-T2`, a small port set; if a complaint reaches you, respond and blacklist the range. A few jurisdictions (e.g. Germany §202c) are stricter — know where you operate.

Random IPv4 is mostly empty — a handful of real captures in the first hour, filling over days. Scale with more ports/threads, or add more scanner nodes (all sharing the same `VIBESCAN_SHARED_KEY`).

### Updating the agent

```bash
# On the scanner host, after pulling new vibescan-go sources
cd vibescan-go/deploy
docker compose -f docker-compose.agent.yml up -d --build
```

---

## CI/CD — deploy on every push to `main` (via **AWS SSM**, no inbound SSH)

The workflow [`.github/workflows/deploy.yml`](../../.github/workflows/deploy.yml):

1. Builds `linux/amd64` → pushes an immutable tag to **ECR**
2. Runs **`aws ssm send-command`** on the EC2 instance (agent phones home over HTTPS)
3. On the host: pin `IMAGE=` in `~/deploy/.env` → `pull` + `up -d` → `migrate` → healthcheck

GitHub never needs port 22. Keep SSH locked to your home IP (or close 22 entirely once SSM works).

### A. One-time: enable SSM on the EC2 instance

**1. Instance role** (you likely already have `vibescan-ec2` for ECR pull). Attach the managed policy:

```bash
aws iam attach-role-policy \
  --role-name vibescan-ec2 \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

If the instance profile is different, attach the same policy to **that** role. The role must already be on the instance (you set `--iam-instance-profile Name=vibescan-ec2` at launch).

**2. SSM Agent** (Ubuntu 24.04 often needs install):

```bash
# SSH in once from your allowed IP (or use EC2 Instance Connect if available)
ssh -i ~/.ssh/vibescan.pem ubuntu@YOUR_EIP

# Install + start (snap package on Ubuntu)
sudo snap install amazon-ssm-agent --classic
sudo systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service
# some images use:  sudo systemctl enable --now amazon-ssm-agent

# Confirm the process is up
systemctl status snap.amazon-ssm-agent.amazon-ssm-agent --no-pager || \
  systemctl status amazon-ssm-agent --no-pager
```

The instance needs **outbound HTTPS (443)** to AWS (default SG egress is fine). No new inbound rules.

**3. Verify the instance is “Online” in SSM** (from your laptop):

```bash
# Find instance id
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=vibescan-web" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' --output text
# → i-0abc…

aws ssm describe-instance-information \
  --filters "Key=InstanceIds,Values=i-0abc…" \
  --query 'InstanceInformationList[0].{Id:InstanceId,Ping:PingStatus,Agent:AgentVersion}' \
  --output table
```

You want **`PingStatus = Online`**. If the list is empty: wait 1–2 minutes, recheck role + agent, reboot once if needed.

**4. Smoke-test a remote command** (no SSH):

```bash
aws ssm send-command \
  --instance-ids i-0abc… \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["whoami","docker ps --format {{.Names}}"]' \
  --query 'Command.CommandId' --output text
# then:
aws ssm get-command-invocation --command-id COMMAND_ID --instance-id i-0abc…
```

**5. Optional — keep SSH locked.** Your current rule (`YOUR_IP/32` on 22) is fine; you do **not** need `0.0.0.0/0` for CI.

### B. One-time: GitHub secrets

Repo → **Settings → Secrets and variables → Actions**:

| Secret | Value |
|--------|--------|
| `AWS_ACCOUNT_ID` | 12-digit account id |
| `AWS_ACCESS_KEY_ID` | CI IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | matching secret |
| `EC2_INSTANCE_ID` | `i-0abc…` (from step A.3) |

You do **not** need `EC2_HOST` / `EC2_USER` / `EC2_SSH_KEY` for this workflow.

**CI IAM user policy** (ECR push + SSM Run Command). Replace `ACCOUNT_ID` and `INSTANCE_ID`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrAuth",
      "Effect": "Allow",
      "Action": ["ecr:GetAuthorizationToken"],
      "Resource": "*"
    },
    {
      "Sid": "EcrPush",
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "ecr:DescribeRepositories"
      ],
      "Resource": "arn:aws:ecr:us-east-1:ACCOUNT_ID:repository/vibescan"
    },
    {
      "Sid": "SsmSend",
      "Effect": "Allow",
      "Action": [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommands",
        "ssm:ListCommandInvocations"
      ],
      "Resource": [
        "arn:aws:ec2:us-east-1:ACCOUNT_ID:instance/INSTANCE_ID",
        "arn:aws:ssm:us-east-1::document/AWS-RunShellScript",
        "arn:aws:ssm:us-east-1:ACCOUNT_ID:*"
      ]
    }
  ]
}
```

Host still needs `~/deploy` with a filled `.env` + compose files + optional `GeoLite2-City.mmdb`. CI only rewrites `IMAGE=` and restarts containers.

### C. Trigger

- **Automatic:** push to `main` that touches `vibescan-go/**`, `vibescan-ui/**`, or the workflow file.
- **Manual:** GitHub → **Actions → Deploy → Run workflow**.

### D. Rollback

Set `IMAGE=` on the host to a prior ECR tag (via one-off SSM command or SSH from home) and:

```bash
cd ~/deploy
docker compose -f docker-compose.registry.yml pull
docker compose -f docker-compose.registry.yml up -d
```

---

## Ops

**Monitoring (the 1 GB box is fragile).** CloudWatch has CPU by default; install the **CloudWatch agent** for memory, then add an **alarm** on CPU/memory (SNS email). Add an external uptime check (e.g. UptimeRobot) on `https://YOUR_DOMAIN/api/healthz`.

**Rate limiting.** Stock Caddy has no rate-limit module. Options: front the site with a CDN/WAF (AWS WAF if you put CloudFront/ALB ahead of the host, or Cloudflare if that’s your DNS), or build a custom Caddy with `caddy-ratelimit`. Ingest (`POST /api/v1/results`) is already HMAC-gated; invalid requests are redirected (307) to `VIBESCAN_PUBLIC_URL` rather than returning a detailed 4xx.

**Backups (M0 has none).** Install MongoDB Database Tools on a machine that can reach Atlas, then cron a dump to a private S3 bucket:

```bash
mongodump --uri="$MONGO_URI" --archive --gzip \
  | aws s3 cp - s3://vibescan-backups/$(date +%F).archive.gz
```

`results` is largely re-scannable, but **votes/tags/users** (once added) are not — treat backups as mandatory before the interactions phase ships.

**Update / rollback (app).** Prefer **push to `main`** (CI/CD above). Manual path still works:

1. Laptop: `cd vibescan-go/deploy && REGION=us-east-1 ACCOUNT_ID=… ./build-push.sh` → note the new pinned tag.
2. Host: set `IMAGE=` in `~/deploy/.env` to that tag, then:

   ```bash
   docker compose -f docker-compose.registry.yml pull
   docker compose -f docker-compose.registry.yml up -d
   ```

3. **Rollback** = set `IMAGE=` back to a prior tag and repeat (old tags remain in ECR). Optionally set an ECR lifecycle policy to expire very old tags.

Indexes are created on startup and via `migrate`; re-running migrate after an upgrade is safe (idempotent).

**Logs.**

```bash
docker compose -f docker-compose.registry.yml logs -f app
docker compose -f docker-compose.registry.yml logs -f caddy
```

Add `VIBESCAN_DEBUG=1` to `.env` and recreate the app container for verbose ingest logging. Container logs are capped at 3×10 MB (compose `logging` block); Caddy access logs go to stdout.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|-------------------|
| **Caddy won’t get a cert** | DNS not pointing at the EIP; Cloudflare proxy still orange; SG missing 80/443; check `logs -f caddy` |
| **Host can’t pull the image** | Instance role missing `AmazonEC2ContainerRegistryReadOnly`; `~/.docker/config.json` credHelper not set for your ECR hostname; wrong `IMAGE=` tag |
| **`migrate` / app can’t reach Atlas** | EIP not in Atlas Network Access; M0 cluster paused; bad password encoding in `MONGO_URI` |
| **Agent 4xx / submit errors** | `VIBESCAN_SHARED_KEY` mismatch; wrong `VIBESCAN_SERVER_URL` (must be base URL, no `/api/...` path); collector down |
| **No images on tiles** | `S3_*` wrong (region/keys/endpoint); IAM user lacks `s3:PutObject`; `S3_PUBLIC_URL` or CloudFront OAC/bucket policy broken — open `/api/v2/image/IP/PORT` and follow the 302 |
| **World map blank** | Missing `GeoLite2-City.mmdb`, or the compose volume mounted an empty dir (comment out the volume if you intentionally skip GeoIP) |
| **UI loads but APIs 404** | Wrong image / old build without embedded UI; confirm `curl …/api/healthz` on the same host |
| **OOM / container restarts on t3.micro** | Something is building on the 1 GB box (use registry flow only); or too many agents hammering a tiny host |

---

## File map (`vibescan-go/deploy/`)

| File | Role |
|------|------|
| `DEPLOY.md` | this runbook |
| `.env.example` | collector / Caddy / S3 / Mongo template → copy to `.env` |
| `agent.env.example` | scanner template → copy to `agent.env` |
| `docker-compose.yml` | build-on-server (app + Caddy) |
| `docker-compose.registry.yml` | pull prebuilt `IMAGE` + Caddy (t3.micro path) |
| `docker-compose.agent.yml` | build & run Go agent on the scanner host |
| `build-push.sh` | cross-build `linux/amd64` app image → ECR |
| `Caddyfile` | `{$DOMAIN}` → reverse_proxy `app:8000` |
| `GeoLite2-City.mmdb` | optional GeoIP DB (gitignored pattern `*.mmdb`) |
