#!/usr/bin/env bash
# baseline-publish.sh: OPERATOR-ONLY tool. Never run by the application.
#
# Downloads the eight VulKG import files at one pinned upstream commit,
# computes SHA-256 and size for each, uploads them to
#   s3://<bucket>/vulkg/<commit>/<scriptName>
# and writes baseline/manifest.json (the Baseline_Manifest).
#
# Usage:
#   scripts/baseline-publish.sh --bucket NAME [--commit SHA40] [--dry-run]
#                               [--manifest PATH] [--workdir DIR]
#
# Environment fallbacks: BSKG_BASELINE_BUCKET, VULKG_COMMIT.
# Without --commit, VulKG main HEAD is resolved once with `git ls-remote` and
# pinned to its 40-hex SHA; every download then uses that SHA.
# --dry-run does everything except the S3 upload (and needs no bucket).
set -euo pipefail

UPSTREAM_REPO="https://github.com/happyResearcher/VulKG"
RAW_BASE="https://raw.githubusercontent.com/happyResearcher/VulKG"
PREFIX_ROOT="vulkg"

# logical | repoName (path in upstream repo) | scriptName (name the load script uses)
# Two upstream files carry the typo "Vulnerabiliy_"; scriptName is the corrected
# name used for the S3 key and the local cache.
FILES=(
  "VulnerabilityNodes|import/VulnerabilityNodes.csv|VulnerabilityNodes.csv"
  "ExploitNodes|import/ExploitNodes.csv|ExploitNodes.csv"
  "HasExploit|import/Vulnerabiliy_HAS_EXPLOIT_Exploit_relationship.csv|Vulnerability_HAS_EXPLOIT_Exploit_relationship.csv"
  "WeaknessNodes|import/WeaknessNodes.csv|WeaknessNodes.csv"
  "VulnerabilityNodesAddProperties|import/VulnerabilityNodesAddProperties.csv|VulnerabilityNodesAddProperties.csv"
  "DomainRefers|import/DomainNodes_Vulnerabiliy_HAS_REFERENCE_Domain_relationship.csv|DomainNodes_Vulnerability_HAS_REFERENCE_Domain_relationship.csv"
  "ProductAffects|import/ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv|ProductNodes_VendorNodes_Vulnerability_AFFECTS_Product_BELONGS_TO_Vendor.csv"
  "AffectsAddProperty|import/AffectsAddProperty.csv|AffectsAddProperty.csv"
)

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

bucket="${BSKG_BASELINE_BUCKET:-}"
commit="${VULKG_COMMIT:-}"
dry_run=0
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
manifest="$repo_root/baseline/manifest.json"
workdir=""

while [ $# -gt 0 ]; do
  case "$1" in
    --bucket)   [ $# -ge 2 ] || die "--bucket needs a value"; bucket="$2"; shift 2 ;;
    --commit)   [ $# -ge 2 ] || die "--commit needs a value"; commit="$2"; shift 2 ;;
    --manifest) [ $# -ge 2 ] || die "--manifest needs a value"; manifest="$2"; shift 2 ;;
    --workdir)  [ $# -ge 2 ] || die "--workdir needs a value"; workdir="$2"; shift 2 ;;
    --dry-run)  dry_run=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

for tool in curl jq sha256sum stat git; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done
if [ "$dry_run" -eq 0 ]; then
  command -v aws >/dev/null 2>&1 || die "required tool not found: aws"
  [ -n "$bucket" ] || die "bucket required: --bucket NAME or BSKG_BASELINE_BUCKET"
fi
# S3 bucket naming rules (3-63 chars, lowercase letters, digits, dots, hyphens).
if [ -n "$bucket" ] && ! [[ "$bucket" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]]; then
  die "invalid bucket name: $bucket"
fi

if [ -z "$commit" ]; then
  commit="$(git ls-remote "$UPSTREAM_REPO" refs/heads/main | cut -f1)"
  echo "resolved VulKG main HEAD to $commit" >&2
fi
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "commit must be a 40-character lowercase hex SHA, got: $commit"

if [ -z "$workdir" ]; then
  workdir="$(mktemp -d)"
  trap 'rm -rf "$workdir"' EXIT
else
  mkdir -p "$workdir"
fi

prefix="$PREFIX_ROOT/$commit/"
entries="$workdir/entries.jsonl"
: > "$entries"

for spec in "${FILES[@]}"; do
  IFS='|' read -r logical repo_name script_name <<<"$spec"
  dest="$workdir/$script_name"
  url="$RAW_BASE/$commit/$repo_name"
  echo "download $repo_name" >&2
  curl --fail --silent --show-error --location --retry 3 --retry-delay 2 \
    --output "$dest" "$url" || die "download failed: $url"
  sum="$(sha256sum "$dest" | cut -d' ' -f1)"
  size="$(stat -c %s "$dest")"
  [ "$size" -ge 1 ] || die "empty file: $repo_name"
  [ "$size" -le 10737418240 ] || die "file too large: $repo_name"
  key="$prefix$script_name"
  if [ "$dry_run" -eq 1 ]; then
    echo "dry-run: would upload $script_name to s3://${bucket:-<bucket>}/$key" >&2
  else
    aws s3 cp --only-show-errors "$dest" "s3://$bucket/$key" \
      || die "upload failed: $key"
  fi
  jq -cn --arg logical "$logical" --arg repoName "$repo_name" \
    --arg scriptName "$script_name" --arg key "$key" --arg sha256 "$sum" \
    --argjson size "$size" \
    '{logical:$logical, repoName:$repoName, scriptName:$scriptName, key:$key, sha256:$sha256, size:$size}' \
    >> "$entries"
done

mkdir -p "$(dirname "$manifest")"
tmp="$manifest.tmp.$$"
jq -n --arg repo "$UPSTREAM_REPO" --arg commit "$commit" \
  --arg copiedOn "$(date -u +%Y-%m-%d)" \
  --arg bucket "${bucket:-}" --arg prefix "$prefix" \
  --slurpfile files "$entries" \
  '{upstream:{repo:$repo, commit:$commit, copiedOn:$copiedOn},
    bucket:{name:$bucket, prefix:$prefix},
    files:$files}' > "$tmp"
mv "$tmp" "$manifest"

echo "wrote $manifest" >&2
if [ "$dry_run" -eq 1 ]; then
  echo "dry-run: nothing was uploaded; bucket.name is '${bucket}' (set it before committing)" >&2
fi
