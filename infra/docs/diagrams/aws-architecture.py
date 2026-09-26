from diagrams import Diagram, Cluster, Edge
from diagrams.aws.network import APIGateway, ELB, InternetGateway, NATGateway
from diagrams.aws.compute import EKS, EC2, AutoScaling
from diagrams.aws.database import Aurora
from diagrams.aws.storage import S3
from diagrams.aws.security import CertificateManager, KMS
from diagrams.aws.management import Cloudwatch
from diagrams.aws.integration import SNS
from diagrams.onprem.network import Internet
from diagrams.onprem.client import User
from diagrams.saas.cdn import Cloudflare

with Diagram(
    "PicoCompute AWS Architecture",
    filename="infra/docs/diagrams/aws-architecture",
    show=False,
    direction="TB",
):
    user = User("User")

    cf = Cloudflare("Cloudflare DNS")

    with Cluster("AWS Cloud"):
        apigw = APIGateway("REST API Gateway")

        with Cluster("VPC"):
            eks = EKS("EKS Fargate\n(pico-api)")

            with Cluster("Control Plane"):
                aurora = Aurora("Aurora\nPostgreSQL 18")

            with Cluster("Compute Hosts (ASG)"):
                compute = AutoScaling("Auto Scaling")
                ec2_1 = EC2("m7i.4xlarge\nAZ-a")
                ec2_2 = EC2("m7i.4xlarge\nAZ-b")

            natgw = NATGateway("Regional NAT\nGateway")
            igw = InternetGateway("IGW")

        with Cluster("Account Services"):
            acm = CertificateManager("ACM")
            artifacts = S3("Artifacts S3")
            snapshots = S3("Snapshots S3")
            kms_res = KMS("KMS Keys")
            cw = Cloudwatch("CloudWatch")
            sns = SNS("SNS Alarms")

    user >> cf >> apigw
    apigw >> eks
    eks >> aurora
    eks >> compute
    compute - ec2_1
    compute - ec2_2
    compute >> natgw >> igw

    eks >> Edge(color="grey") << artifacts
    compute >> Edge(color="grey") << artifacts
