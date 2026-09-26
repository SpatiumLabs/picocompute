# PicoCompute v2 API Examples

Examples for CLI and SDK consumers. All examples assume:

- API base URL: `https://api.picocompute.dev/v2`
- Authentication: `Authorization: Bearer <token>` header on every request
- Tenant context: `PicoCompute-Tenant: <tenant_id>` header on every request
- Idempotency: `Idempotency-Key: <unique_key>` header on mutating requests
- Access leases: `PicoCompute-Access-Lease: <signed_lease>` header on exec/stream/file requests

## Shell/curl

### Create a sandbox

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: create-$(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "runtime": "firecracker",
    "image": "alpine-linux-6.1",
    "vcpus": 2,
    "memory_mb": 512,
    "idle_timeout_secs": 300,
    "ports": [8080]
  }'
```

Response (synchronous completion):

```json
{
  "operation_id": "op_01JXYZ123456789",
  "sandbox_id": "sbx_01JXYZABCDEFGH",
  "action": "create",
  "status": "completed",
  "state": "Running",
  "result": {
    "id": "sbx_01JXYZABCDEFGH",
    "state": "Running",
    "runtime": "firecracker",
    "image": "alpine-linux-6.1",
    "vcpus": 2,
    "memory_mb": 512,
    "idle_timeout_secs": 300,
    "ports": [
      {"guest_port": 8080, "host_port": 32001, "host_address": "127.0.0.1"}
    ],
    "created_at": "2026-06-09T12:00:00Z",
    "last_activity_at": "2026-06-09T12:00:00Z",
    "labels": {},
    "failure": null,
    "request_id": "req_01JXYZ123456789"
  },
  "status_url": "/v2/operations/op_01JXYZ123456789",
  "created_at": "2026-06-09T12:00:00Z",
  "updated_at": "2026-06-09T12:00:05Z",
  "request_id": "req_01JXYZ123456789"
}
```

### Fork from an existing sandbox

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: fork-$(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "image": "alpine-linux-6.1",
    "source_sandbox_id": "sbx_01JXYZAAAAAAAA",
    "vcpus": 4,
    "memory_mb": 1024
  }'
```

### Poll a long-running operation

```bash
# After receiving a 202 with an operation_id
OPERATION_ID="op_01JXYZ123456789"

while true; do
  STATUS=$(curl -s https://api.picocompute.dev/v2/operations/$OPERATION_ID \
    -H "Authorization: Bearer $PICO_TOKEN" \
    -H "PicoCompute-Tenant: my-tenant")

  STATE=$(echo "$STATUS" | jq -r '.status')
  echo "Operation $STATE"

  if [ "$STATE" = "completed" ] || [ "$STATE" = "failed" ]; then
    echo "$STATUS" | jq .
    break
  fi
  sleep 2
done
```

### List sandboxes

```bash
curl -s https://api.picocompute.dev/v2/sandboxes \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant"
```

With filters:

```bash
curl -s "https://api.picocompute.dev/v2/sandboxes?state=Running&runtime=firecracker&limit=10" \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant"
```

### Get sandbox status

```bash
curl -s https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant"
```

### Exec a command

First obtain an access lease:

```bash
LEASE=$(curl -s -X POST https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/lease \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Content-Type: application/json" \
  -d '{"action": "exec"}' | jq -r '.lease')
```

Then execute:

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/exec \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: exec-$(uuidgen)" \
  -H "PicoCompute-Access-Lease: $LEASE" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "python",
    "args": ["-c", "print(sum(range(100)))"],
    "timeout_secs": 30
  }'
```

Response:

```json
{
  "exit_code": 0,
  "stdout": "4950\n",
  "stderr": "",
  "duration_ms": 14,
  "request_id": "req_01JXYZ123456789"
}
```

### Suspend a sandbox

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/suspend \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: suspend-$(uuidgen)"
```

### Resume a sandbox

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/resume \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: resume-$(uuidgen)"
```

### Expose a port

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/ports \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: port-$(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"guest_port": 8080}'
```

Response:

```json
{
  "sandbox_id": "sbx_01JXYZABCDEFGH",
  "guest_port": 8080,
  "host_port": 32001,
  "host_address": "127.0.0.1",
  "request_id": "req_01JXYZ123456789"
}
```

### Read a file

```bash
curl -s "https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/files?path=/home/user/main.py" \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "PicoCompute-Access-Lease: $LEASE"
```

### Write a file

```bash
curl -s -X PUT https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/files \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: file-$(uuidgen)" \
  -H "PicoCompute-Access-Lease: $LEASE" \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/home/user/config.yaml",
    "content": "debug: true\nport: 3000\n"
  }'
```

### Destroy a sandbox

```bash
curl -s -X DELETE https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: destroy-$(uuidgen)"
```

### Idempotency replay

Repeating a request with the same `Idempotency-Key` returns the original result:

```bash
# First request creates the sandbox
SANDBOX=$(curl -s -X POST https://api.picocompute.dev/v2/sandboxes \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: my-unique-key-001" \
  -H "Content-Type: application/json" \
  -d '{"image": "alpine-linux-6.1"}')

echo "$SANDBOX" | jq .sandbox_id
# "sbx_01JXYZABCDEFGH"

# Second request with the same key returns the same sandbox
SANDBOX2=$(curl -s -X POST https://api.picocompute.dev/v2/sandboxes \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: my-unique-key-001" \
  -H "Content-Type: application/json" \
  -d '{"image": "alpine-linux-6.1"}')

echo "$SANDBOX2" | jq .sandbox_id
# "sbx_01JXYZABCDEFGH"  (same sandbox, no new sandbox created)
```

## Error handling

### State conflict (sandbox not in correct state for operation)

```bash
curl -s -X POST https://api.picocompute.dev/v2/sandboxes/sbx_01JXYZABCDEFGH/exec \
  -H "Authorization: Bearer $PICO_TOKEN" \
  -H "PicoCompute-Tenant: my-tenant" \
  -H "Idempotency-Key: exec-$(uuidgen)" \
  -H "PicoCompute-Access-Lease: $LEASE" \
  -H "Content-Type: application/json" \
  -d '{"command": "echo hello"}'
```

Response (409):

```json
{
  "error": {
    "code": "state_conflict",
    "message": "Sandbox must be Running to exec (current state: Suspended)",
    "details": {
      "current_state": "Suspended",
      "required_states": ["Running"]
    },
    "request_id": "req_01JXYZ123456789"
  }
}
```

### Quota exceeded

```json
{
  "error": {
    "code": "quota_exceeded",
    "message": "Tenant sandbox limit (10) reached",
    "details": {
      "limit": 10,
      "current": 10,
      "resource": "sandbox_count"
    },
    "request_id": "req_01JXYZ123456789"
  }
}
```

### Access denied (expired lease)

```json
{
  "error": {
    "code": "access_denied",
    "message": "Lease expired at 2026-06-09T12:05:00Z",
    "request_id": "req_01JXYZ123456789"
  }
}
```

## Python SDK Example

```python
import os
import time
import requests
from uuid import uuid4

API_BASE = "https://api.picocompute.dev/v2"
HEADERS = {
    "Authorization": f"Bearer {os.environ['PICO_TOKEN']}",
    "PicoCompute-Tenant": os.environ['PICO_TENANT'],
}

def create_sandbox(image, vcpus=2, memory_mb=512, idle_timeout_secs=300,
                   source_sandbox_id=None, ports=None):
    """Create a new sandbox. Returns the sandbox resource."""
    payload = {
        "image": image,
        "vcpus": vcpus,
        "memory_mb": memory_mb,
        "idle_timeout_secs": idle_timeout_secs,
    }
    if source_sandbox_id:
        payload["source_sandbox_id"] = source_sandbox_id
    if ports:
        payload["ports"] = ports

    resp = requests.post(
        f"{API_BASE}/sandboxes",
        headers={
            **HEADERS,
            "Idempotency-Key": str(uuid4()),
            "Content-Type": "application/json",
        },
        json=payload,
    )
    resp.raise_for_status()

    if resp.status_code == 202:
        return wait_for_operation(resp.json()["operation_id"])
    return resp.json()["result"]

def wait_for_operation(operation_id):
    """Poll until a long-running operation completes."""
    while True:
        resp = requests.get(
            f"{API_BASE}/operations/{operation_id}",
            headers=HEADERS,
        )
        resp.raise_for_status()
        op = resp.json()

        if op["status"] == "completed":
            return op["result"]
        if op["status"] == "failed":
            raise RuntimeError(f"Operation failed: {op['error']}")

        time.sleep(2)

def exec_command(sandbox_id, command, args=None, timeout_secs=30):
    """Execute a command inside a sandbox."""
    lease = _acquire_lease(sandbox_id, "exec")
    resp = requests.post(
        f"{API_BASE}/sandboxes/{sandbox_id}/exec",
        headers={
            **HEADERS,
            "Idempotency-Key": str(uuid4()),
            "PicoCompute-Access-Lease": lease,
            "Content-Type": "application/json",
        },
        json={
            "command": command,
            "args": args or [],
            "timeout_secs": timeout_secs,
        },
    )
    resp.raise_for_status()
    return resp.json()

def _acquire_lease(sandbox_id, action):
    """Obtain an access lease for a sandbox action."""
    resp = requests.post(
        f"{API_BASE}/sandboxes/{sandbox_id}/lease",
        headers={
            **HEADERS,
            "Content-Type": "application/json",
        },
        json={"action": action},
    )
    resp.raise_for_status()
    return resp.json()["lease"]

# Usage
sandbox = create_sandbox("alpine-linux-6.1", vcpus=2, ports=[8080])
print(f"Sandbox {sandbox['id']} is {sandbox['state']}")

result = exec_command(sandbox["id"], "python", ["-c", "print(2 + 2)"])
print(f"Exit: {result['exit_code']}, stdout: {result['stdout'].strip()}")
```

## Go SDK Example

```go
package picocompute

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "time"
)

const APIBase = "https://api.picocompute.dev/v2"

type Client struct {
    Token  string
    Tenant string
}

func NewClientFromEnv() *Client {
    return &Client{
        Token:  os.Getenv("PICO_TOKEN"),
        Tenant: os.Getenv("PICO_TENANT"),
    }
}

func (c *Client) CreateSandbox(image string, vcpus, memoryMB int, ports []int) (*Sandbox, error) {
    payload := map[string]interface{}{
        "image":      image,
        "vcpus":      vcpus,
        "memory_mb":  memoryMB,
        "ports":      ports,
    }
    body, _ := json.Marshal(payload)

    resp, err := c.request("POST", "/sandboxes", body)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode == 202 {
        var op Operation
        json.NewDecoder(resp.Body).Decode(&op)
        return c.WaitForOperation(op.OperationID)
    }

    var op Operation
    json.NewDecoder(resp.Body).Decode(&op)
    return op.Result, nil
}

func (c *Client) Exec(sandboxID, command string, args []string) (*ExecResponse, error) {
    lease, _ := c.AcquireLease(sandboxID, "exec")
    payload := map[string]interface{}{
        "command":   command,
        "args":      args,
    }
    body, _ := json.Marshal(payload)

    resp, err := c.requestWithLease("POST",
        fmt.Sprintf("/sandboxes/%s/exec", sandboxID),
        body, lease)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result ExecResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}

func (c *Client) request(method, path string, body []byte) (*http.Response, error) {
    req, _ := http.NewRequest(method, APIBase+path, bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+c.Token)
    req.Header.Set("PicoCompute-Tenant", c.Tenant)
    req.Header.Set("Content-Type", "application/json")
    return http.DefaultClient.Do(req)
}

func (c *Client) requestWithLease(method, path string, body []byte, lease string) (*http.Response, error) {
    resp, err := c.request(method, path, body)
    if err == nil {
        resp.Request.Header.Set("PicoCompute-Access-Lease", lease)
    }
    return resp, err
}
```
