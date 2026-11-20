#!/bin/bash
# BSKG host bootstrap. Writes no secrets and does not start the stack.
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl git gnupg xfsprogs

# Docker and the Compose plugin from Docker's apt repository.
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
usermod -aG docker ubuntu || true

# Locate the data volume (NVMe name differs from the attachment device name).
DEV=""
for i in $(seq 1 60); do
  for cand in /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${data_volume_id_nodash}* /dev/sdf /dev/xvdf; do
    if [ -e "$cand" ]; then DEV="$(readlink -f "$cand")"; break 2; fi
  done
  sleep 2
done
if [ -z "$DEV" ]; then echo "data volume not found" >&2; exit 1; fi

# Format once only.
if ! blkid "$DEV" >/dev/null 2>&1; then
  mkfs.xfs "$DEV"
fi
mkdir -p /data
UUID="$(blkid -s UUID -o value "$DEV")"
grep -q "$UUID" /etc/fstab || echo "UUID=$UUID /data xfs defaults,nofail 0 2" >> /etc/fstab
mountpoint -q /data || mount /data

# Neo4j runs as uid 7474.
mkdir -p /data/neo4j
chown 7474:7474 /data/neo4j

# Clone the repository. No credentials are used or stored.
if [ ! -d /opt/bskg/.git ]; then
  git clone --branch "${repo_ref}" "${repo_url}" /opt/bskg
fi
chown -R ubuntu:ubuntu /opt/bskg

# The operator copies deploy/.env to the host and runs: docker compose up -d
echo "BSKG bootstrap complete. Stack not started." > /var/log/bskg-bootstrap.done
