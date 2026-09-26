# Terraform IAM Permissions

Minimal policy for applying the full PicoCompute AWS infrastructure.

## Broad Policy (CI/CD)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Resource": "*",
      "Action": [
        "ec2:*",
        "eks:*",
        "ecr:*",
        "rds:*",
        "s3:*",
        "kms:*",
        "iam:*",
        "elasticloadbalancing:*",
        "autoscaling:*",
        "cloudwatch:*",
        "logs:*",
        "backup:*",
        "ssm:*",
        "acm:*",
        "wafv2:*",
        "apigateway:*",
        "guardduty:*",
        "securityhub:*",
        "cloudtrail:*",
        "sts:GetCallerIdentity"
      ]
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::*:role/pico-*"
    }
  ]
}
```

## Per-Service Breakdown

### Networking (VPC, Subnets, NAT, Endpoints)

| Action | Purpose |
|---|---|
| `ec2:CreateVpc` | VPC |
| `ec2:DeleteVpc` | Teardown |
| `ec2:DescribeVpcs` | Plan/read |
| `ec2:ModifyVpcAttribute` | DNS hostnames/support |
| `ec2:CreateSubnet` | Public/private subnets |
| `ec2:DeleteSubnet` | Teardown |
| `ec2:DescribeSubnets` | Plan/read |
| `ec2:CreateInternetGateway` | IGW |
| `ec2:DeleteInternetGateway` | Teardown |
| `ec2:AttachInternetGateway` / `ec2:DetachInternetGateway` | IGW ↔ VPC |
| `ec2:AllocateAddress` / `ec2:ReleaseAddress` | EIP (if zonal NAT) |
| `ec2:CreateNatGateway` / `ec2:DeleteNatGateway` | NAT Gateway |
| `ec2:DescribeNatGateways` | Plan/read |
| `ec2:CreateRouteTable` / `ec2:DeleteRouteTable` | Route tables |
| `ec2:CreateRoute` / `ec2:DeleteRoute` | Routes |
| `ec2:AssociateRouteTable` / `ec2:DisassociateRouteTable` | Subnet associations |
| `ec2:CreateNetworkAcl` / `ec2:DeleteNetworkAcl` | NACLs |
| `ec2:CreateNetworkAclEntry` / `ec2:DeleteNetworkAclEntry` | NACL rules |
| `ec2:CreateVpcEndpoint` / `ec2:DeleteVpcEndpoints` | VPC endpoints (S3, SSM) |
| `ec2:DescribeVpcEndpoints` | Plan/read |
| `ec2:CreateSecurityGroup` / `ec2:DeleteSecurityGroup` | Security groups |
| `ec2:AuthorizeSecurityGroupIngress` / `ec2:RevokeSecurityGroupIngress` | SG rules |
| `ec2:CreateFlowLogs` / `ec2:DeleteFlowLogs` | VPC flow logs |

### Compute (EC2, ASG, Launch Templates)

| Action | Purpose |
|---|---|
| `ec2:CreateLaunchTemplate` / `ec2:DeleteLaunchTemplate` | Launch templates |
| `autoscaling:CreateAutoScalingGroup` / `autoscaling:DeleteAutoScalingGroup` | ASGs |
| `autoscaling:UpdateAutoScalingGroup` | Scaling |
| `autoscaling:PutScalingPolicy` / `autoscaling:DeletePolicy` | Target tracking |
| `ec2:DescribeInstances` | Plan/read |
| `ec2:CreateTags` / `ec2:DeleteTags` | Tagging |

### EKS

| Action | Purpose |
|---|---|
| `eks:CreateCluster` / `eks:DeleteCluster` | EKS cluster |
| `eks:DescribeCluster` | Plan/read |
| `eks:CreateFargateProfile` / `eks:DeleteFargateProfile` | Fargate profiles |
| `eks:CreateAddon` / `eks:DeleteAddon` | Addons (CNI, CoreDNS, LB Controller) |
| `eks:DescribeAddon` | Plan/read |
| `iam:CreateOpenIdConnectProvider` / `iam:DeleteOpenIdConnectProvider` | OIDC for IRSA |

### ECR

| Action | Purpose |
|---|---|
| `ecr:CreateRepository` / `ecr:DeleteRepository` | Container registry |
| `ecr:PutImageScanningConfiguration` | Image scanning |
| `ecr:PutLifecyclePolicy` | Lifecycle policy |

### Load Balancing (ALB, NLB)

| Action | Purpose |
|---|---|
| `elasticloadbalancing:CreateLoadBalancer` / `elasticloadbalancing:DeleteLoadBalancer` | ALB/NLB |
| `elasticloadbalancing:CreateTargetGroup` / `elasticloadbalancing:DeleteTargetGroup` | Target groups |
| `elasticloadbalancing:CreateListener` / `elasticloadbalancing:DeleteListener` | Listeners |
| `elasticloadbalancing:Describe*` | Plan/read |

### Database (Aurora PostgreSQL)

| Action | Purpose |
|---|---|
| `rds:CreateDBCluster` / `rds:DeleteDBCluster` | Aurora cluster |
| `rds:CreateDBInstance` / `rds:DeleteDBInstance` | Cluster instances |
| `rds:CreateDBSubnetGroup` / `rds:DeleteDBSubnetGroup` | Subnet group |
| `rds:CreateDBClusterParameterGroup` / `rds:DeleteDBClusterParameterGroup` | Parameter group |
| `rds:ModifyDBCluster` / `rds:ModifyDBInstance` | Updates |
| `rds:Describe*` | Plan/read |

### Storage (S3)

| Action | Purpose |
|---|---|
| `s3:CreateBucket` / `s3:DeleteBucket` | Buckets (artifacts, snapshots, ALB logs, CloudTrail) |
| `s3:PutBucketVersioning` | Versioning |
| `s3:PutBucketPublicAccessBlock` | Public access blocks |
| `s3:PutBucketPolicy` / `s3:DeleteBucketPolicy` | Bucket policies |
| `s3:PutEncryptionConfiguration` | SSE-S3 / SSE-KMS |
| `s3:GetBucket*` | Plan/read |

### Encryption (KMS)

| Action | Purpose |
|---|---|
| `kms:CreateKey` / `kms:ScheduleKeyDeletion` | KMS keys (artifacts, snapshots, backup, CloudTrail, EKS) |
| `kms:CreateAlias` / `kms:DeleteAlias` | Key aliases |
| `kms:EnableKeyRotation` | Key rotation |
| `kms:PutKeyPolicy` / `kms:GetKeyPolicy` | Key policies |
| `kms:DescribeKey` | Plan/read |

### IAM

| Action | Purpose |
|---|---|
| `iam:CreateRole` / `iam:DeleteRole` | Roles (EC2, ECS, EKS, Fargate, Backup, SSM, RDS monitoring) |
| `iam:CreatePolicy` / `iam:DeletePolicy` | Inline/customer-managed policies |
| `iam:AttachRolePolicy` / `iam:DetachRolePolicy` | Managed policy attachments |
| `iam:PutRolePolicy` / `iam:DeleteRolePolicy` | Inline policies |
| `iam:CreateInstanceProfile` / `iam:DeleteInstanceProfile` | EC2 instance profiles |
| `iam:AddRoleToInstanceProfile` / `iam:RemoveRoleFromInstanceProfile` | Profile associations |
| `iam:GetRole` / `iam:GetPolicy` / `iam:List*` | Plan/read |
| `iam:PassRole` | Pass roles to services (restrict to `pico-*` pattern) |

### API Gateway

| Action | Purpose |
|---|---|
| `apigateway:POST` | Create REST API, resources, methods, integrations |
| `apigateway:DELETE` | Teardown |
| `apigateway:GET` / `apigateway:PATCH` | Read/update |
| `apigateway:PUT` | Deployments, stages, API keys |

### Monitoring & Observability

| Action | Purpose |
|---|---|
| `cloudwatch:PutDashboard` / `cloudwatch:DeleteDashboards` | Ops dashboard |
| `cloudwatch:PutMetricAlarm` / `cloudwatch:DeleteAlarms` | Alarms |
| `logs:CreateLogGroup` / `logs:DeleteLogGroup` | Log groups (flow logs, ECS, EKS) |
| `logs:PutRetentionPolicy` | Retention settings |

### Backup & DR

| Action | Purpose |
|---|---|
| `backup:CreateBackupVault` / `backup:DeleteBackupVault` | Backup vault |
| `backup:CreateBackupPlan` / `backup:DeleteBackupPlan` | Backup plan |
| `backup:CreateBackupSelection` / `backup:DeleteBackupSelection` | Resource selection |

### Security & Detective Controls

| Action | Purpose |
|---|---|
| `wafv2:CreateWebACL` / `wafv2:DeleteWebACL` | WAF web ACL |
| `wafv2:AssociateWebACL` / `wafv2:DisassociateWebACL` | WAF ↔ ALB association |
| `guardduty:CreateDetector` / `guardduty:DeleteDetector` | GuardDuty |
| `securityhub:EnableSecurityHub` / `securityhub:DisableSecurityHub` | Security Hub |
| `cloudtrail:CreateTrail` / `cloudtrail:DeleteTrail` | CloudTrail |
| `cloudtrail:StartLogging` / `cloudtrail:StopLogging` | Trail logging |

### SSM

| Action | Purpose |
|---|---|
| `ssm:CreatePatchBaseline` / `ssm:DeletePatchBaseline` | Patch baseline |
| `ssm:CreateMaintenanceWindow` / `ssm:DeleteMaintenanceWindow` | Maintenance window |
| `ssm:RegisterTargetWithMaintenanceWindow` | Window targets |
| `ssm:RegisterTaskWithMaintenanceWindow` | Window tasks |

### Certificate & DNS

| Action | Purpose |
|---|---|
| `acm:RequestCertificate` / `acm:DeleteCertificate` | ACM certs |
| `acm:DescribeCertificate` | Plan/read |

## Notes

- `iam:PassRole` must be scoped to `pico-*` roles only to avoid privilege escalation
- For `terraform destroy`, all `Create` actions need corresponding `Delete` actions
- EKS addons are managed in-cluster by the AWS LB Controller after initial creation - no explicit IAM action needed
- Cloudflare DNS records are managed by the Cloudflare provider, not AWS IAM
