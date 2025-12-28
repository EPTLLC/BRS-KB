#!/usr/bin/env python3

"""
BRS-KB CI/CD Setup Script
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easyprotech)
Dev: Brabus
Date: Sat 25 Oct 2025 12:00:00 UTC
Status: Created
Telegram: https://t.me/easyprotech

Automated CI/CD pipeline setup for GitHub Actions, GitLab CI, and Jenkins
"""

import os
import subprocess
from pathlib import Path


# Version from single source
try:
    from brs_kb.version import __version__ as BRS_KB_VERSION
except ImportError:
    BRS_KB_VERSION = "4.0.0"  # Fallback


def setup_github_actions():
    """Set up GitHub Actions workflow"""
    print(" Setting up GitHub Actions...")

    # Create .github/workflows directory
    workflows_dir = Path(".github/workflows")
    workflows_dir.mkdir(parents=True, exist_ok=True)

    # Copy CI workflow
    ci_file = Path(".github/workflows/ci.yml")
    if not ci_file.exists():
        print(" CI workflow file not found")
        return False

    print(" GitHub Actions workflow already configured")

    return True


def setup_gitlab_ci():
    """Set up GitLab CI configuration"""
    print(" Setting up GitLab CI...")

    gitlab_ci_file = Path(".gitlab-ci.yml")
    if not gitlab_ci_file.exists():
        print(" GitLab CI configuration file not found")
        return False

    print(" GitLab CI configuration ready")

    return True


def setup_jenkins():
    """Set up Jenkins pipeline"""
    print(" Setting up Jenkins...")

    jenkins_file = Path("Jenkinsfile")
    if not jenkins_file.exists():
        print(" Jenkins configuration file not found")
        return False

    print(" Jenkins pipeline ready")

    return True


def configure_git():
    """Configure Git for CI/CD"""
    print(" Configuring Git for CI/CD...")

    try:
        # Check if we're in a git repository
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip() != "true":
            print(" Not in a Git repository")
            return False

        # Configure Git user for CI/CD
        subprocess.run(
            ["git", "config", "user.name", "BRS-KB CI/CD"], check=True, capture_output=True
        )
        subprocess.run(
            ["git", "config", "user.email", "cicd@brs-kb.local"], check=True, capture_output=True
        )

        print(" Git configured for CI/CD")

        return True

    except subprocess.CalledProcessError:
        print(" Git configuration failed")
        return False


def create_deployment_scripts():
    """Create deployment automation scripts"""
    print(" Creating deployment scripts...")

    scripts_dir = Path("scripts")
    scripts_dir.mkdir(exist_ok=True)

    # Create deployment script
    deployment_script = """
#!/bin/bash
# BRS-KB Deployment Script

set -e

echo " Deploying BRS-KB..."

# Install package
pip install -e .

# Run tests
python -m pytest tests/ -v

# Validate installation
python -c "import brs_kb; print(' BRS-KB installed successfully')"

# Test CLI
brs-kb info | head -3

echo " BRS-KB deployment completed successfully!"
"""

    with open(scripts_dir / "deploy.sh", "w") as f:
        f.write(deployment_script)

    # Make executable
    os.chmod(scripts_dir / "deploy.sh", 0o755)

    print(" Deployment scripts created")

    return True


def create_docker_files():
    """Create Docker configuration for containerized deployment"""
    print(" Creating Docker configuration...")

    # Create Dockerfile
    dockerfile_content = """FROM python:3.10-slim

LABEL maintainer="EasyProTech LLC <contact@easyprotech>"
LABEL version="{BRS_KB_VERSION}"
LABEL description="BRS-KB XSS Intelligence Platform"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Install BRS-KB
RUN pip install -e .

# Create non-root user
RUN useradd --create-home --shell /bin/bash brs-kb
USER brs-kb

# Expose port for web interface (if added later)
# EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["brs-kb"]
CMD ["info"]
"""

    with open("Dockerfile", "w") as f:
        f.write(dockerfile_content)

    # Create docker-compose.yml
    docker_compose_content = """version: '3.8'

services:
  brs-kb:
    build: .
    container_name: brs-kb
    volumes:
      - ./data:/app/data
    environment:
      - BRS_KB_ENV=production
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "python", "-c", "import brs_kb; print('OK')"]
      interval: 30s
      timeout: 10s
      retries: 3
"""

    with open("docker-compose.yml", "w") as f:
        f.write(docker_compose_content)

    print(" Docker configuration created")

    return True


def create_kubernetes_manifests():
    """Create Kubernetes deployment manifests"""
    print(" Creating Kubernetes manifests...")

    k8s_dir = Path("k8s")
    k8s_dir.mkdir(exist_ok=True)

    # Create deployment
    deployment_content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: brs-kb
  labels:
    app: brs-kb
spec:
  replicas: 2
  selector:
    matchLabels:
      app: brs-kb
  template:
    metadata:
      labels:
        app: brs-kb
    spec:
      containers:
      - name: brs-kb
        image: brs-kb:latest
        ports:
        - containerPort: 8000
        env:
        - name: BRS_KB_ENV
          value: "production"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command:
            - python
            - -c
            - "import brs_kb; print('OK')"
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
"""

    with open(k8s_dir / "deployment.yaml", "w") as f:
        f.write(deployment_content)

    # Create service
    service_content = """apiVersion: v1
kind: Service
metadata:
  name: brs-kb-service
  labels:
    app: brs-kb
spec:
  selector:
    app: brs-kb
  ports:
  - name: http
    port: 80
    targetPort: 8000
  type: ClusterIP
"""

    with open(k8s_dir / "service.yaml", "w") as f:
        f.write(service_content)

    # Create ingress
    ingress_content = """apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: brs-kb-ingress
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - brs-kb.company.com
    secretName: brs-kb-tls
  rules:
  - host: brs-kb.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: brs-kb-service
            port:
              number: 80
"""

    with open(k8s_dir / "ingress.yaml", "w") as f:
        f.write(ingress_content)

    print(" Kubernetes manifests created")

    return True


def create_monitoring_config():
    """Create monitoring and alerting configuration"""
    print(" Creating monitoring configuration...")

    monitoring_dir = Path("monitoring")
    monitoring_dir.mkdir(exist_ok=True)

    # Create Prometheus configuration
    prometheus_config = """global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts.yml"

scrape_configs:
  - job_name: 'brs-kb'
    static_configs:
      - targets: ['brs-kb:8000']
    scrape_interval: 30s
    metrics_path: /metrics
"""

    with open(monitoring_dir / "prometheus.yml", "w") as f:
        f.write(prometheus_config)

    # Create alert rules
    alerts_config = """groups:
  - name: brs-kb
    rules:
    - alert: BRSDBHighErrorRate
      expr: rate(brs_kb_errors_total[5m]) > 0.1
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "High error rate in BRS-KB"
        description: "BRS-KB is experiencing {{ $value }} errors per second"

    - alert: BRSDBCriticalErrorRate
      expr: rate(brs_kb_errors_total[5m]) > 0.5
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Critical error rate in BRS-KB"
        description: "BRS-KB is experiencing {{ $value }} errors per second"

    - alert: BRSDBLowPayloadDatabase
      expr: brs_kb_payloads_total < 100
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Low payload database count"
        description: "BRS-KB payload database has {{ $value }} payloads (minimum 100)"
"""

    with open(monitoring_dir / "alerts.yml", "w") as f:
        f.write(alerts_config)

    print(" Monitoring configuration created")

    return True


def create_security_policies():
    """Create security policies and configurations"""
    print(" Creating security policies...")

    security_dir = Path("security")
    security_dir.mkdir(exist_ok=True)

    # Create security policy
    security_policy = """# BRS-KB Security Policy

## Authentication
- API keys required for sensitive operations
- JWT tokens for user sessions
- OAuth2 integration supported

## Authorization
- Role-based access control (RBAC)
- Context-specific permissions
- Audit logging for all actions

## Data Protection
- Input sanitization and validation
- SQL injection prevention
- XSS protection mechanisms
- CSRF protection

## Network Security
- HTTPS only in production
- CORS configuration
- Rate limiting
- DDoS protection

## Monitoring
- Security event logging
- Vulnerability scanning
- Compliance monitoring
- Incident response
"""

    with open(security_dir / "SECURITY_POLICY.md", "w") as f:
        f.write(security_policy)

    print(" Security policies created")

    return True


def main():
    """Main CI/CD setup function"""
    print(" BRS-KB CI/CD Pipeline Setup")
    print("=" * 50)
    print()

    setup_steps = [
        ("GitHub Actions", setup_github_actions),
        ("GitLab CI", setup_gitlab_ci),
        ("Jenkins Pipeline", setup_jenkins),
        ("Git Configuration", configure_git),
        ("Deployment Scripts", create_deployment_scripts),
        ("Docker Configuration", create_docker_files),
        ("Kubernetes Manifests", create_kubernetes_manifests),
        ("Monitoring Configuration", create_monitoring_config),
        ("Security Policies", create_security_policies),
    ]

    success_count = 0
    for step_name, step_func in setup_steps:
        print(f" Setting up {step_name}...")
        if step_func():
            print(f" {step_name} configured successfully")
            success_count += 1
        else:
            print(f" {step_name} configuration failed")
        print()

    print("=" * 50)
    print(" CI/CD Setup Complete!")
    print(f" {success_count}/{len(setup_steps)} components configured")

    if success_count == len(setup_steps):
        print("🎊 All CI/CD components ready for deployment!")
        print()
        print(" Next steps:")
        print("   1. Commit changes to Git repository")
        print("   2. Push to trigger CI/CD pipeline")
        print("   3. Monitor automated builds and tests")
        print("   4. Deploy to production environment")
        print()
        print("📚 Documentation:")
        print("   • GitHub Actions: .github/workflows/ci.yml")
        print("   • GitLab CI: .gitlab-ci.yml")
        print("   • Jenkins: Jenkinsfile")
        print("   • Deployment: scripts/deploy.sh")
        print("   • Docker: Dockerfile, docker-compose.yml")
        print("   • Kubernetes: k8s/ directory")
        print("   • Monitoring: monitoring/ directory")
    else:
        print(f" {len(setup_steps) - success_count} components failed setup")
        print("Please review the errors and fix configuration")

    return success_count == len(setup_steps)


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
