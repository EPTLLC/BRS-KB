#!/usr/bin/env python3

"""
PyPI Publication Script
Project: BRS-KB (BRS XSS Knowledge Base)
Company: EasyProTech LLC (www.easypro.tech)
Dev: Brabus
Date: 2025-10-26
Status: Created
Telegram: https://t.me/easyprotech
"""

import os
import subprocess
import sys


def publish_to_pypi():
    """Publish package to PyPI"""
    print("Publishing BRS-KB to PyPI...")

    # Check if .pypirc exists
    pypirc_path = os.path.expanduser("~/.pypirc")
    if not os.path.exists(pypirc_path):
        print("ERROR: .pypirc file not found. Please run:")
        print("   python3 scripts/setup_pypi.py")
        print("   Or set TWINE_PASSWORD environment variable")
        return False

    try:
        # Clean previous builds
        if os.path.exists("dist"):
            print("Cleaning previous builds...")
            subprocess.run(["rm", "-rf", "dist"], check=True)

        # Build the package
        print("Building package...")
        subprocess.run([sys.executable, "-m", "build", "--outdir", "dist"], check=True)

        # Check the package
        print("Checking package...")
        subprocess.run([sys.executable, "-m", "twine", "check", "dist/*"], check=True)

        # Upload to PyPI
        print("Uploading to PyPI...")
        result = subprocess.run(
            [sys.executable, "-m", "twine", "upload", "dist/*"], capture_output=True, text=True
        )

        if result.returncode == 0:
            print("Successfully published to PyPI!")
            print("Package available at: https://pypi.org/project/brs-kb/")
            return True
        else:
            print(f"Upload failed: {result.stderr}")
            return False

    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False


def setup_pypi():
    """Setup PyPI configuration"""
    print("Setting up PyPI configuration...")
    print("")
    print("IMPORTANT: Store your PyPI token securely!")
    print("Recommended methods:")
    print("  1. Use environment variable: TWINE_PASSWORD=your-token")
    print("  2. Create ~/.pypirc with secure permissions (600)")
    print("")
    print("~/.pypirc format:")
    print("[distutils]")
    print("index-servers = pypi")
    print("")
    print("[pypi]")
    print("username = __token__")
    print("password = your-pypi-token-here")
    print("")
    print("After creating ~/.pypirc, run: chmod 600 ~/.pypirc")

    return True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        success = setup_pypi()
    else:
        success = publish_to_pypi()

    sys.exit(0 if success else 1)
