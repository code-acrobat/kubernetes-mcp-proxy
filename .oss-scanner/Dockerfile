# Build/test image for external scanners (OSS Scanner convention:
# `dockerfile: .oss-scanner/Dockerfile` in project.yaml). Also works
# as a plain build check: `docker build -f .oss-scanner/Dockerfile .`
# The proxy itself has zero runtime deps (one .mjs file); this image
# provides the toolchain the offline test suite needs (node, jq, curl).
FROM node:22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      jq curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Everything the audit needs must be inside the image: the scan phase
# runs with no Internet access. Both suites are fully offline.
RUN sh tests/validate.sh && sh tests/e2e.sh
