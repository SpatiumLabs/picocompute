#!/usr/bin/env bash
# Delete the pre-cutover api-stg namespace on the production EKS cluster.
# Run only after the dedicated staging cluster is serving traffic.
# Then set retire_shared_staging_namespace=true and apply production.
set -euo pipefail

cluster="${1:-picocompute-production}"
region="${2:-us-east-1}"

aws eks update-kubeconfig --name "$cluster" --region "$region" >/dev/null
kubectl delete namespace api-stg --wait=true
echo "Deleted api-stg on ${cluster}. Set retire_shared_staging_namespace=true and apply production."
