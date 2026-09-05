# Deploy to AWS ECS Fargate

This is a deployment runbook, not a claim of an existing AWS deployment. AWS resources incur charges. The application image serves the React dashboard and API on port 8000.

## Architecture

Internet → HTTPS ALB → private ECS Fargate task → private RDS PostgreSQL.
CloudWatch receives container logs. Secrets Manager holds API_KEY and DATABASE_URL.
Prometheus and Grafana in Compose are local observability services; deploy them privately or use managed monitoring for AWS.

1. Create an ECR repository named cloudsentinel in your chosen region.
2. Create an RDS PostgreSQL database named sentinel, with a dedicated application user. Keep it private. Set DATABASE_URL to `postgresql+psycopg://USER:PASSWORD@HOST:5432/sentinel?sslmode=require` (URL-encode credentials).
3. Store API_KEY and DATABASE_URL as separate Secrets Manager secrets containing plain string values. Do not paste secrets into GitHub or task-definition JSON.
4. Create an ECS task execution role with AmazonECSTaskExecutionRolePolicy and narrowly scoped secretsmanager:GetSecretValue on these two secrets (and kms:Decrypt if using a customer-managed KMS key). The application task role can be empty: this version receives logs over HTTP and does not call AWS APIs.
5. Build and push the image using the commands below. Replace every uppercase placeholder.
6. Copy `infra/task-definition.json` to a local file and replace placeholders for region, account, image digest, execution role, and secret ARNs. Create the /ecs/cloudsentinel log group first.
7. Register the task definition with `aws ecs register-task-definition --cli-input-json file://YOUR_TASK_FILE.json`.
8. Create an ECS cluster and Fargate service using private subnets with NAT or the required ECR, Secrets Manager, and CloudWatch VPC endpoints. Start with one task. Set task security-group ingress to port 8000 from the ALB security group only.
9. Create an ALB target group of type ip on port 8000 with health check /health. Attach it to the service's api container port 8000. Configure an HTTPS listener with an ACM certificate. Forward only /api/*, /health, /docs, /openapi.json, /assets/* and / to the service; do not expose /metrics to the internet. Alternatively put authenticated access in front of the entire service.
10. Allow RDS ingress on 5432 only from the ECS task security group. Verify /health, authenticated ingestion, dashboard loading, and CloudWatch logs before recording a deployment as successful.

```bash
aws ecr create-repository --repository-name cloudsentinel --region REGION
aws ecr get-login-password --region REGION | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com
docker build --platform linux/amd64 -t cloudsentinel .
docker tag cloudsentinel:latest ACCOUNT.dkr.ecr.REGION.amazonaws.com/cloudsentinel:VERSION
docker push ACCOUNT.dkr.ecr.REGION.amazonaws.com/cloudsentinel:VERSION
```

Use the pushed image digest in the task definition for reproducible releases. Roll back by updating the service to the previous task-definition revision. Delete the service, ALB, unused ECR images, and database when finished; decide explicitly whether to retain a final RDS snapshot.

## Production follow-up

This MVP uses a shared API key, serial ingestion, synchronous inference, and startup table creation. Before production add OIDC/RBAC, per-tenant isolation, schema migrations, rate limiting and body-size limits, retention policies, queue-based ingestion, managed model artifacts, drift monitoring, and a calibrated model trained on representative approved data. Keep raw logs outside LLM prompts. Pin and scan container images regularly.

Official references:
- [FastAPI containers](https://fastapi.tiangolo.com/deployment/docker/)
- [ECS execution role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html)
- [ECS application task role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)
