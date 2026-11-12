#!/usr/bin/env bash
# Delete the pre-cutover api-stg namespace on the production EKS cluster.
# Run only after the dedicated staging cluster is serving traffic.
set -euo pipefail

cluster="${1:-picocompute-production}"
region="${2:-us-east-1}"

aws eks update-kubeconfig --name "$cluster" --region "$region" >/dev/null
kubectl delete namespace api-stg --wait=true --ignore-not-found
echo "Deleted api-stg on ${cluster} (if it existed)."
