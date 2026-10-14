*This project has been created as part of the 42 curriculum by hloureda, airzane.*

# Cloud Audit: Automated CSPM Pipeline

Cloud Audit is an automated Cloud Security Posture Management (CSPM) auditing pipeline designed to evaluate enterprise cloud environments against the Center for Internet Security (CIS) Benchmarks. Built upon Prowler and LocalStack, the solution scans AWS infrastructure for security misconfigurations, reduces operational noise through strict severity filtering, and generates actionable executive reports accompanied by verified remediation playbooks.

---

## Table of Contents

- [Description](#description)
  - [Architecture and Workflow](#architecture-and-workflow)
  - [CIS Benchmark Coverage](#cis-benchmark-coverage)
- [Instructions](#instructions)
  - [Prerequisites](#prerequisites)
  - [System and Tool Setup](#system-and-tool-setup)
  - [Environment Configuration](#environment-configuration)
  - [LocalStack Deployment and Seeding](#localstack-deployment-and-seeding)
  - [Pipeline Execution](#pipeline-execution)
- [Automation and Continuous Auditing](#automation-and-continuous-auditing)
- [Blocking Cases Handled](#blocking-cases-handled)
  - [API Rate Limiting and Backoff](#api-rate-limiting-and-backoff)
  - [Authentication Timeouts and Failures](#authentication-timeouts-and-failures)
  - [Scan Noise and False Positives](#scan-noise-and-false-positives)
- [Remediation Strategy](#remediation-strategy)
  - [Playbook Architecture](#playbook-architecture)
  - [Zero-Downtime Deployment Methodology](#zero-downtime-deployment-methodology)
- [Resources](#resources)
  - [References](#references)
  - [AI Usage Declaration](#ai-usage-declaration)

---

## Description

In modern cloud environments, configuration drift and overly permissive access policies pose severe security risks. Cloud Audit simulates an internal security auditor assessing a cloud sandbox. It executes non-destructive, read-only compliance assessments against the CIS AWS Foundations Benchmark, consolidates raw findings, filters out benign results, and exports formatted compliance reports.

### Architecture and Workflow

```
+-----------------------------------------------------------------------------------+
|                                Cloud Audit Pipeline                               |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  1. Authenticate       2. Audit Scan           3. Noise Reduction  4. Reporting   |
|  +--------------+      +-----------------+     +-----------------+ +------------+ |
|  | Load .env    | ---> | Run Prowler     | --> | Filter Status   | | Generate   | |
|  | Validate AWS |      | CIS 3.0 AWS     |     | Parse ASFF/JSON | | HTML/CSV   | |
|  | Credentials  |      | Read-only mode  |     | Severity Cutoff | | Reports    | |
|  +--------------+      +-----------------+     +-----------------+ +------------+ |
|                                                                          |        |
|                                                                          v        |
|  6. Archive            5. Alerting                                                |
|  +-------------------+ +--------------------------------------------------------+ |
|  | organize_output.py| | discord_alert.py (Dispatch Webhook Alerts)             | |
|  | audit_<timestamp>/| +--------------------------------------------------------+ |
|  +-------------------+                                                            |
+-----------------------------------------------------------------------------------+
```

1. **Authentication**: Ingests read-only credentials via environment variables (`.env` or system environment). Hardcoded credentials are strictly avoided.
2. **Scan Execution**: Triggers Prowler in read-only mode targeting the CIS 3.0 AWS benchmark, producing raw AWS Security Finding Format (ASFF) JSON data.
3. **Filtering and Parsing**: Ingests raw scan data, filters out `PASS` and `INFO` checks, and extracts failures meeting the specified severity threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
4. **Executive Reporting**: Compiles findings into an interactive HTML dashboard with dynamic filtering and consolidated audit statistics.
5. **Notification Dispatch**: Translates critical and high-severity findings into formatted notifications dispatched via secure webhook endpoints.
6. **Artifact Archiving**: Isolates raw data, compliance records, and generated dashboards into timestamped directories (`audit_YYYY-MM-DD_HH-MM-SS/`).

### CIS Benchmark Coverage

The pipeline detects and provides remediation procedures for core benchmark checks:

| CIS ID | Vulnerability Description | Severity | Risk Profile |
|---|---|---|---|
| **1.9** | Ensure IAM password policy requires minimum configuration | HIGH | Credential stuffing and brute-force vulnerability |
| **1.14** | Ensure no IAM user has AdministratorAccess and active access keys | CRITICAL | Permanent programmatic privilege compromise |
| **2.1.1** | Ensure S3 bucket policies do not permit public read access | CRITICAL | Unauthorized sensitive data exfiltration |
| **4.1** | Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 | HIGH | Direct exposure of compute instances to SSH exploits |

---

## Instructions

### Prerequisites

- **Operating System**: Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+) or Windows 10/11 with WSL2
- **Python**: Version 3.13 or higher
- **Docker**: Engine 24.0+ and Docker Compose v2 (to host LocalStack)
- **AWS CLI**: Version 2.x
- **Prowler**: Version 3.x / 4.x

### System and Tool Setup

#### 1. AWS CLI Installation

On Linux or Windows WSL2:
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip -q awscliv2.zip
sudo ./aws/install
rm -rf aws awscliv2.zip
```

#### 2. Prowler Installation

Install Prowler in an isolated environment or via pipx:
```bash
python3 -m pip install --upgrade pip
python3 -m pip install prowler
```

Verify the installation:
```bash
prowler -v
```

### Environment Configuration

The pipeline strictly manages credentials through environment variables.

1. Create a local configuration file from the template:
   ```bash
   cp .env.example .env
   ```

2. Configure [.env](file:///home/aliirzane/Downloads/1abdec17050a7ad7627b56636a8461e6/Cloud-Audit-main/.env):
   ```bash
   # AWS / LocalStack credentials
   AWS_ACCESS_KEY_ID=test
   AWS_SECRET_ACCESS_KEY=test
   AWS_DEFAULT_REGION=us-east-1
   AWS_ENDPOINT_URL=http://localhost:4566

   # Optional Alerting Webhook
   WEBHOOK_URL=https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN

   # Pipeline Defaults
   TARGET_ENVIRONMENT=sandbox-01
   COMPLIANCE_FRAMEWORK=cis
   SEVERITY_FILTER=CRITICAL
   OUTPUT_FORMAT=html
   ```

3. Export the variables into your shell session:
   ```bash
   set -a
   source .env
   set +a
   ```

### LocalStack Deployment and Seeding

1. Start the LocalStack container:
   ```bash
   docker run -d \
     --name localstack-audit \
     -p 4566:4566 \
     -p 4510-4559:4510-4559 \
     -e SERVICES=iam,s3,ec2 \
     localstack/localstack:latest
   ```

2. Seed the mock environment with vulnerable infrastructure:
   ```bash
   python3 scripts/seed_vulnerable_env.py
   ```
   *Note: This script is idempotent and can be executed repeatedly across LocalStack restarts without state corruption.*

### Pipeline Execution

#### Running via Makefile

The repository includes a consolidated Makefile orchestrating the complete lifecycle:

```bash
# Run complete audit pipeline (scan, report generation, archive)
make all

# Run individual components
make scan      # Execute Prowler scan against CIS 3.0 AWS Benchmarks
make report    # Generate custom HTML report with interactive filters
make organize  # Move output into timestamped audit directory
```

#### Running Alerting and Notifications

To run the scan and dispatch structured finding summaries via webhook:
```bash
python3 discord_alert.py
```

#### Viewing Reports

Once generated, reports can be reviewed in any standard browser:
```bash
# Local report
xdg-open custom_report.html

# Archived reports
xdg-open audit_*/custom_report.html
```

---

## Automation and Continuous Auditing

To maintain continuous security posture visibility, the audit pipeline can be deployed on an automated cron schedule.

### Cron Job Setup (Linux / macOS / WSL)

1. Open the user crontab editor:
   ```bash
   crontab -e
   ```

2. Add a scheduled entry (e.g., executing daily at 02:00 AM):
   ```bash
   0 2 * * * cd /path/to/Cloud-Audit && /usr/bin/make all >> /var/log/cloud-audit.log 2>&1
   ```

3. Ensure standard output and error logging are directed to an auditable system log location:
   ```bash
   tail -f /var/log/cloud-audit.log
   ```

---

## Blocking Cases Handled

Enterprise cloud auditing environments frequently encounter operational anomalies. The pipeline handles three primary blocking conditions:

### API Rate Limiting and Backoff

- **Problem**: Cloud providers enforce strict API call limits per second/token bucket across IAM, EC2, and S3 APIs. Rapid enumeration triggers `ThrottlingException`, `RequestLimitExceeded`, or HTTP 429 errors.
- **Handling**:
  - The pipeline uses read-only batched requests.
  - Subprocess calls and API clients implement exponential backoff with randomized jitter (e.g., base wait of 2s, doubling to 4s, 8s up to 3 retries).
  - Prowler execution flags (`--ignore-exit-code-3`) prevent pipeline termination when non-fatal provider limits are encountered.

### Authentication Timeouts and Failures

- **Problem**: Expired temporary session tokens, unavailable instance metadata service (IMDS), or missing environment variables cause runtime failures mid-audit.
- **Handling**:
  - Pre-flight validation confirms the presence of `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_DEFAULT_REGION` prior to spawning scanners.
  - Execution scripts provide explicit diagnostics identifying missing parameters rather than dumping stack traces.
  - Subprocess executions maintain a 120-second timeout threshold to abort unresponsive network sessions gracefully.

### Scan Noise and False Positives

- **Problem**: Broad compliance scans often report hundreds of informational findings or flag non-exploitable configurations, overwhelming security operations.
- **Handling**:
  - The parsing engine discards all `PASS` evaluations and informational records.
  - Findings are categorized by explicit severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
  - Strict condition filtering prevents false positives:
    - **S3 Public Read**: Verified exclusively via explicit wildcard principal policies (`Principal: "*"` with `Effect: "Allow"`), ignoring restricted bucket ACLs.
    - **Admin IAM Users**: Flags only principals holding both the managed `AdministratorAccess` policy and an active, long-lived access key.

---

## Remediation Strategy

### Playbook Architecture

Remediation documentation is located within the [remediation_playbooks/](file:///home/aliirzane/Downloads/1abdec17050a7ad7627b56636a8461e6/Cloud-Audit-main/remediation_playbooks) directory:

- [cis-1-9-iam-password-policy.md](file:///home/aliirzane/Downloads/1abdec17050a7ad7627b56636a8461e6/Cloud-Audit-main/remediation_playbooks/cis-1-9-iam-password-policy.md)
- [cis-1-14-iam-overprivileged-user.md](file:///home/aliirzane/Downloads/1abdec17050a7ad7627b56636a8461e6/Cloud-Audit-main/remediation_playbooks/cis-1-14-iam-overprivileged-user.md)
- [cis-2-1-1-s3-public-bucket.md](file:///home/aliirzane/Downloads/1abdec17050a7ad7627b56636a8461e6/Cloud-Audit-main/remediation_playbooks/cis-2-1-1-s3-public-bucket.md)
- [cis-4-1-ec2-open-ssh.md](file:///home/aliirzane/Downloads/1abdec17050a7ad7627b56636a8461e6/Cloud-Audit-main/remediation_playbooks/cis-4-1-ec2-open-ssh.md)

Each playbook adheres to a standardized structure:
1. **Finding Overview**: Contextual definition of the misconfiguration and severity attribution.
2. **Threat Assessment**: Detailed explanation of exploitation mechanics and attack surfaces.
3. **Remediation via AWS CLI**: Direct, copy-paste shell commands for emergency mitigation.
4. **Remediation via Terraform (IaC)**: Declarative configurations for permanent remediation within codebases.
5. **Verification**: CLI validation commands ensuring the finding has been resolved.
6. **Deployment Impact**: Assessment of potential downtime, dependencies, and rollout precautions.

### Zero-Downtime Deployment Methodology

Remediation must not disrupt production workloads. The security operations team adheres to the following workflow:

```
[ Triage Finding ] -> [ Staging Validation ] -> [ Maintenance Scheduling ] -> [ Apply Fix ] -> [ Verification & Re-scan ]
```

1. **Read-Only Separation**: The auditing pipeline never modifies live infrastructure. Findings are strictly diagnostic.
2. **Staging Verification**: Every Terraform modification or CLI command is executed first against a sandbox or non-production environment.
3. **Phased Revocation**:
   - For IAM credential rotation, credentials are set to `Inactive` before deletion, enabling instantaneous rollbacks if an unmapped dependent service is identified.
   - For Security Group rules (e.g., port 22), replacement bastion hosts or SSM Session Manager agents are deployed prior to rule revocation.
4. **Scheduled Maintenance Windows**: Access revocation and bucket policy changes are scheduled during approved off-peak maintenance intervals.
5. **Post-Remediation Scan**: Following deployment, the audit pipeline is re-run to confirm that the finding status transitions from `FAIL` to resolved.

---

## Resources

### References

- [CIS Amazon Web Services Foundations Benchmark v3.0.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [Prowler Open Source Security Tool](https://github.com/prowler-cloud/prowler)
- [LocalStack Cloud Development Framework](https://docs.localstack.cloud/)
- [AWS Security Best Practices Documentation](https://docs.aws.amazon.com/security/)
- [Terraform AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)

### AI Usage Declaration

In accordance with Chapter II and Chapter VII of the project guidelines, AI tools were utilized during development under strict human supervision:

- **Code Acceleration**: Assisted in generating repetitive HTML table structures, DOM filtering scripts, and parsing boilerplate.
- **Playbook Outlining**: Aided in drafting initial command templates and Terraform definitions for standard CIS remediations.
- **Verification and Review**: All AI-assisted output was validated against official AWS CLI and CIS documentation. Scripts were executed and tested against live LocalStack instances to verify behavior. Full responsibility for the implementation and code quality remains with the author.
