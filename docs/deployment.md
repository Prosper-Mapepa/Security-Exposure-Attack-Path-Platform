# Deployment

Nothing in this repository applies infrastructure automatically.

## Docker

`docker compose up` starts PostgreSQL, Redis, the API, the worker, and the web app on localhost ports. The lab profile is separate and published only on `127.0.0.1:8090`.

## Kubernetes

Manifests in `infrastructure/kubernetes` expect a secret named `seap-runtime` containing `DATABASE_URL`, `REDIS_URL`, `JWT_ACCESS_SECRET`, and `MFA_ENCRYPTION_KEY`. Replace the image names before applying. Do not commit that secret.

## AWS

`infrastructure/terraform` sketches a VPC, public and private subnets, an internet gateway, an ALB security group, private RDS PostgreSQL, private ElastiCache Redis, a private S3 bucket, an ECS cluster, and a task role that can write only to the report bucket and to the `/seap/*` log group.

Estimated monthly cost for the smallest sizes in us-east-1, before traffic and NAT:

- RDS `db.t4g.micro`: about $12–15
- ElastiCache `cache.t4g.micro`: about $12
- Application load balancer: about $18 plus LCU
- One NAT gateway, if added for private tasks: about $32 plus data
- Two small Fargate tasks: about $15–25

Requirements: an AWS account, Terraform 1.6+, a remote state bucket you control, and secrets supplied through variables or a secret manager. Copy `terraform.tfvars.example` and replace the password. Run `terraform plan` only after review. Do not run `terraform apply` from CI without an explicit approval environment.

The Terraform does not create overly broad IAM such as `s3:*` or `iam:*`. ECS task execution wiring still needs the container image URI for the environment you publish.
