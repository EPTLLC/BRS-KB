
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
