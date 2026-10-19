#!/bin/sh
# Bring up the compose stack, apply examples/terraform, and require an empty second plan.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

mkdir -p .demo/tls .demo/osquery
if [ ! -f .demo/tls/server.crt ] || [ ! -f .demo/tls/server.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
    -keyout .demo/tls/server.key -out .demo/tls/server.crt \
    -subj "/CN=server" \
    -addext "subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1"
fi
printf '%s\n' "example-enroll-secret" > .demo/osquery/enroll.secret
chmod 644 .demo/osquery/enroll.secret .demo/tls/server.crt
cp deploy/osquery/osquery.flags .demo/osquery/osquery.flags

if [ -w /etc/hosts ] || command -v sudo >/dev/null 2>&1; then
  if ! grep -q '[[:space:]]dex$' /etc/hosts; then
    echo "127.0.0.1 dex" | sudo tee -a /etc/hosts >/dev/null
  fi
fi

# Compose publishes Postgres on 5432. A host Postgres must not hold that port.
if command -v pg_isready >/dev/null 2>&1 && pg_isready -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
  if command -v pg_ctlcluster >/dev/null 2>&1; then
    sudo pg_ctlcluster 16 main stop || true
  fi
fi

docker compose up -d --build

echo "waiting for Mission Control"
i=0
while [ "$i" -lt 60 ]; do
  if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 3
done
curl -fsS http://127.0.0.1:8080/healthz >/dev/null

make build tf-dev
export TF_CLI_CONFIG_FILE="${ROOT}/bin/dev.tfrc"
terraform -chdir=examples/terraform apply -auto-approve
set +e
terraform -chdir=examples/terraform plan -detailed-exitcode -out=/dev/null
code=$?
set -e
if [ "$code" -ne 0 ]; then
  echo "second terraform plan was not empty (exit ${code})" >&2
  exit 1
fi
echo "demo stack is up and the second plan is empty"
