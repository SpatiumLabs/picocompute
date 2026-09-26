# pico-edge: Data Plane Architecture

`pico-edge` is the session proxy that handles client-to-sandbox traffic. It sits between users and compute hosts, validating access leases before forwarding HTTP/WebSocket connections to the sandbox TCP backend.

## Flow

```
Client → pico-edge (TLS) → pico-host-agent:9000 → sandbox (Firecracker/QEMU)
              │
              ├── LeaseManager (lease validation)
              └── AuditEventSink (connection audit trail)
```

## Functions

| Function | Detail |
|---|---|
| TLS termination | Client-facing HTTPS for sandbox sessions |
| Lease validation | Checks `x-pico-lease-id` header against `pico-core::LeaseManager` |
| Host routing | Maps `Host` header to upstream compute host address via `RoutingTable` |
| WebSocket | Transparent HTTP→WS upgrade for bidirectional streaming (Pingora) |
| Rate limiting | Token-bucket per-hostname RPS + global connection cap |
| Connection limiting | Atomic global concurrent connection cap |
| Audit | Emits `NetworkEnforcement` events (allow/deny) per connection |
| Graceful reload | Pingora SIGHUP-based zero-downtime reload with connection draining |

## Control Plane vs Data Plane

```
┌─ Control plane (deployed) ─────────────────────────────────────┐
│ User → API Gateway → EKS Fargate (pico-api) → Aurora        │
│ Sandbox CRUD, lease management, auth                            │
└─────────────────────────────────────────────────────────────────┘

┌─ Data plane (NOT yet deployed) ────────────────────────────────┐
│ Client → pico-edge (TLS) → pico-host-agent:9000 → sandbox│
│ Lease validation, WebSocket proxy, session routing              │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

| Option | Default | Description |
|---|---|---|
| `listen_addr` | `0.0.0.0:8080` | HTTP listen address |
| `listen_addr_tls` | none | HTTPS listen address |
| `tls_cert` | none | PEM certificate path |
| `tls_key` | none | PEM key path |
| `default_upstream` | `127.0.0.1:9000` | Fallback TCP upstream |
| `default_max_rps` | `100` | Per-hostname rate limit |
| `max_connections` | `10000` | Global connection cap |
| `workers` | CPU count | Pingora worker threads |
| `policy_epoch` | `1` | Lease policy epoch for rotation |

## Deployment (Not Yet Implemented)

### EKS Fargate Pod

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pico-edge
  namespace: api
spec:
  replicas: 2
  template:
    spec:
      serviceAccountName: edge
      containers:
      - name: edge
        image: {ecr}/pico-edge:latest
        ports:
        - containerPort: 8080
        - containerPort: 8443
        volumeMounts:
        - name: tls
          mountPath: /etc/pico-edge
          readOnly: true
        env:
        - name: EDGE_DEFAULT_UPSTREAM
          value: pico-host-agent:9000
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            cpu: 256m
            memory: 256Mi
          limits:
            memory: 512Mi
      volumes:
      - name: tls
        secret:
          secretName: pico-edge-tls
---
apiVersion: v1
kind: Service
metadata:
  name: pico-edge
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: nlb
    service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing
spec:
  type: LoadBalancer
  ports:
  - port: 443
    targetPort: 8443
    protocol: TCP
  selector:
    app: pico-edge
```

### Infrastructure Changes Required

1. **CI/CD**: Build `pico-edge` binary, push to ECR
2. **ACM**: Certificate for edge domain (e.g. `sandbox.domain.com`)
3. **Cloudflare DNS**: CNAME pointing to edge NLB
4. **k8s TLS secret**: Mount ACM cert as Kubernetes secret
5. **IRSA**: Service account with S3 access (for audit log export, if needed)

## Host Discovery

```
Client requests sandbox → pico-api returns sandbox metadata:
  {
    sandboxId: "sbox-abc",
    host: "compute-east-1a.internal",
    port: 9001,
    leaseId: "lease-xyz",
    tenantId: "tenant-123"
  }

Client connects to:
  wss://sandbox.domain.com/session
  Headers:
    Host: sbox-abc.sandbox.domain.com
    x-pico-lease-id: lease-xyz
    x-pico-tenant-id: tenant-123
    x-pico-sandbox-id: sbox-abc
    x-pico-guest-port: 22 (SSH) or 7681 (ttyd)

pico-edge:
  1. Validates lease (LeaseManager)
  2. Looks up Host header → compute host IP (RoutingTable)
  3. Proxies TCP to compute east-1a.internal:9001
  4. Emits audit event (allow/deny)
```

### RoutingTable Population

The `RoutingTable` maps sandbox identifiers to compute host upstreams. Options for populating it:

| Approach | Complexity | Latency |
|---|---|---|
| **Static config file** (TOML) | Low | Instant on reload |
| **Shared Redis/memcached** | Medium | <1ms |
| **Service mesh** (Consul/Linkerd) | High | <1ms |
| **API callback** (edge queries pico-api) | Medium | ~10ms |
| **gRPC stream** (api pushes to edge) | Medium | <1ms |

Recommended: start with static config or API callback, evolve to gRPC stream for real-time updates.

## Dependencies

| Crate | Role |
|---|---|
| `pico-core` | LeaseManager, LeaseAction, AuditEventSink, domain types |
| `pico-host-agent` | Port-forward endpoints on compute hosts (TCP, not a crate dep) |
| `pingora-core` / `pingora-proxy` | HTTP proxy framework (Cloudflare) |
| `tokio`, `serde`, `clap`, `tracing` | Standard runtime |

## TODOs

- **Audit sink**: Currently hardcoded to `InMemoryAuditSink`. Should support `ChannelAuditSink` or `PostgresAuditSink`.
- **Per-endpoint rate/connection limits**: `Upstream.max_rps` and `max_connections` fields are defined but not enforced (uses global defaults).
- **Path-based routing**: Only `Host` header matching is implemented; path-prefix routing is future work.
- **Dynamic routing table**: Currently static; needs API-driven population.
