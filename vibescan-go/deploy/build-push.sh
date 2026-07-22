#!/usr/bin/env bash
# Build the app image for linux/amd64 and push it to Amazon ECR.
# Run this on your workstation (NOT the small server). Your Mac is arm64 but the
# EC2 host is amd64, so we cross-build with --platform linux/amd64.
#
# One-time AWS setup (see deploy/DEPLOY.md):
#   aws ecr create-repository --repository-name vibescan --region $REGION
#
# Usage:
#   REGION=us-east-1 ACCOUNT_ID=123456789012 ./build-push.sh
set -euo pipefail

REGION="${REGION:?set REGION, e.g. us-east-1 (match your EC2 region)}"
ACCOUNT_ID="${ACCOUNT_ID:?set ACCOUNT_ID to your 12-digit AWS account id}"
REPO="${REPO:-vibescan}"
# Immutable, sortable tag by default (never :latest, so releases are pinnable and
# rollback = point IMAGE back to a prior tag). Override with TAG=… if you like.
TAG="${TAG:-$(date -u +%Y%m%d-%H%M%S)}"
REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
IMAGE="${REGISTRY}/${REPO}:${TAG}"

# Repo root = two levels up from this script (vibescan-go/deploy/).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Log Docker in to ECR (the token lasts 12h).
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

# buildx needs a container-driver builder to --push (the default docker driver
# can't). Create one once; reuse it thereafter.
if ! docker buildx inspect vibescan >/dev/null 2>&1; then
  docker buildx create --name vibescan --driver docker-container --bootstrap >/dev/null
fi

echo "Building ${IMAGE} (linux/amd64) from ${ROOT} …"
docker buildx --builder vibescan build \
  --platform linux/amd64 \
  -f "${ROOT}/vibescan-go/Dockerfile" \
  -t "${IMAGE}" \
  --push \
  "${ROOT}"

echo
echo "Pushed: ${IMAGE}"
echo "On the server, pin this exact tag in deploy/.env:"
echo "  IMAGE=${IMAGE}"
