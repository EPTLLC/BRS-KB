# BRS-KB CI/CD Configuration

This directory contains continuous integration and continuous deployment configurations for BRS-KB.

## Available CI/CD Platforms

### GitHub Actions (`.github/workflows/ci.yml`)
**Primary CI/CD platform for BRS-KB**

**Features:**
- Multi-Python version testing (3.8-3.12)
- Code quality checks (linting, type checking)
- Security scanning and dependency checks
- Package building and distribution
- Integration testing
- Automated releases
- Performance benchmarking

**Workflow Stages:**
1. **Lint** - Code quality and formatting
2. **Security** - Vulnerability and dependency scanning
3. **Test** - Multi-version testing with coverage
4. **Build** - Package creation and artifact generation
5. **Integration** - End-to-end testing
6. **Deploy** - Release and distribution

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main`
- Daily scheduled runs
- Manual workflow dispatch

### GitLab CI (`.gitlab-ci.yml`)
**Alternative CI/CD configuration for GitLab**

**Features:**
- Parallel testing across Python versions
- Code coverage reporting
- Package building and deployment
- Documentation deployment (GitLab Pages)
- Performance testing
- Security scanning

**Stages:**
1. **lint** - Code quality checks
2. **test** - Multi-version testing
3. **security** - Vulnerability scanning
4. **build** - Package creation
5. **deploy** - PyPI and container deployment

### Jenkins Pipeline (`Jenkinsfile`)
**Enterprise CI/CD pipeline for Jenkins**

**Features:**
- Declarative pipeline syntax
- Parallel stage execution
- Artifact management
- Notification integration
- Release management
- Performance monitoring

**Stages:**
1. **Setup** - Environment preparation
2. **Code Quality** - Parallel linting and security
3. **Testing** - Coverage and integration testing
4. **Build** - Package creation
5. **Integration** - End-to-end testing
6. **Performance** - Load and performance testing
7. **Deploy** - Environment-specific deployment

## Quick Start

### GitHub Actions
```bash
# Push to main branch to trigger pipeline
git push origin main

# Manual trigger
# Go to GitHub Actions tab and click "workflow_dispatch"
```

### GitLab CI
```bash
# Push to any branch to trigger pipeline
git push origin feature-branch

# Manual trigger via GitLab UI
# Go to CI/CD > Pipelines and click "Run pipeline"
```

### Jenkins
```bash
# Configure Jenkins job with this repository
# Pipeline will trigger on push to configured branches
```

## Configuration

### Environment Variables
Set these in your CI/CD platform:

```bash
# Python version matrix
PYTHON_VERSIONS="3.8,3.9,3.10,3.11,3.12"

# Code quality thresholds
MIN_COVERAGE=85
MAX_COMPLEXITY=10

# Security settings
ENABLE_SECURITY_SCAN=true
DEPENDENCY_CHECK=true

# Deployment settings
PYPI_TOKEN=your_pypi_token
DOCKER_REGISTRY=your_registry
```

### Customizing Workflows

#### GitHub Actions
Edit `.github/workflows/ci.yml` to:
- Add/remove Python versions
- Modify test commands
- Add custom stages
- Configure notifications

#### GitLab CI
Edit `.gitlab-ci.yml` to:
- Change stage order
- Modify parallel execution
- Add custom jobs
- Configure artifacts

#### Jenkins
Edit `Jenkinsfile` to:
- Add/remove stages
- Configure notifications
- Set up credentials
- Customize deployment

## Integration Examples

### Security Scanning Integration
```yaml
# GitHub Actions example
- name: Run BRS-KB Security Tests
  run: |
    python -m pytest tests/ -v
    python -c "from brs_kb import validate_payload_database"
```

### Package Building
```yaml
# GitHub Actions example
- name: Build Package
  run: python -m build

- name: Upload to PyPI
  run: twine upload dist/*
```

### Docker Building
```yaml
# GitHub Actions example
- name: Build Docker Image
  run: docker build -t brs-kb:${{ github.sha }} .
```

## Monitoring & Alerting

### GitHub Actions
- **Status checks** on pull requests
- **Required checks** for merge protection
- **Branch protection** rules
- **GitHub API** notifications

### GitLab CI
- **Pipeline status** badges
- **Merge request** integration
- **GitLab Pages** for reports
- **Slack/Discord** notifications

### Jenkins
- **Build status** indicators
- **Email notifications**
- **Slack integration**
- **Custom dashboards**

## Troubleshooting

### Common Issues

**GitHub Actions:**
- **Python version not found**: Check `setup-python` action version
- **Package build fails**: Verify `pyproject.toml` configuration
- **Test timeouts**: Increase timeout in workflow

**GitLab CI:**
- **Memory issues**: Adjust `before_script` resource usage
- **Cache problems**: Clear GitLab CI cache
- **Runner issues**: Check runner configuration

**Jenkins:**
- **Pipeline syntax**: Validate with Jenkins Pipeline Linter
- **Credentials**: Verify credential bindings
- **Workspace**: Check disk space and permissions

### Debug Mode
Enable debug logging in workflows:

```yaml
env:
  ACTIONS_STEP_DEBUG: true
  ACTIONS_RUNNER_DEBUG: true
```

### Support

For CI/CD issues:
- **GitHub Actions**: GitHub Community Discussions
- **GitLab CI**: GitLab CI/CD Documentation
- **Jenkins**: Jenkins Community

For BRS-KB CI/CD issues:
- Check GitHub Issues: https://github.com/easypro-tech/BRS-KB/issues
- Contact: https://t.me/easyprotech

## Best Practices

### Security
- **Never** commit secrets to code
- Use **encrypted secrets** for API keys
- **Rotate tokens** regularly
- **Audit access** to CI/CD systems

### Performance
- **Cache dependencies** between builds
- **Parallel execution** where possible
- **Resource optimization** for large test suites
- **Matrix testing** for compatibility

### Maintenance
- **Regular updates** of CI/CD configurations
- **Version pinning** for stability
- **Documentation updates** for changes
- **Monitoring and alerting** setup

## Version Compatibility

| Platform | BRS-KB Version | Minimum Version | Status |
|----------|---------------|----------------|---------|
| GitHub Actions | 2.0.0+ | actions/checkout@v4 | Active |
| GitLab CI | 2.0.0+ | 15.0+ | Active |
| Jenkins | 2.0.0+ | 2.400+ | Active |

## Contributing

To contribute CI/CD improvements:

1. Fork the repository
2. Create feature branch
3. Modify CI/CD configurations
4. Test changes locally
5. Submit pull request

## License

CI/CD configurations are released under the MIT License, same as BRS-KB.

---

**Made by EasyProTech LLC**  
**BRS-KB: Professional XSS Intelligence Platform**
