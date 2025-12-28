#!/usr/bin/env python3

"""
Test script for PyPI publication
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


def test_pypi_publication():
    """Test PyPI publication process"""
    print("🔍 Testing PyPI publication process...")

    # Check if .pypirc exists
    pypirc_path = os.path.expanduser("~/.pypirc")
    if not os.path.exists(pypirc_path):
        print(" .pypirc file not found")
        return False

    print(" .pypirc file exists")

    # Build the package
    print(" Building package...")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "build", "--outdir", "dist"],
            capture_output=True,
            text=True,
            cwd=".",
        )

        if result.returncode != 0:
            print(f" Build failed: {result.stderr}")
            return False

        print(" Package built successfully")

        # Check the built package
        print("🔍 Checking package...")
        result = subprocess.run(
            [sys.executable, "-m", "twine", "check", "dist/*"], capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f" Package check failed: {result.stderr}")
            return False

        print(" Package check passed")

        # List built files
        files = [f for f in os.listdir("dist") if f.endswith((".whl", ".tar.gz"))]
        print(f" Built files: {files}")

        return True

    except Exception as e:
        print(f" Error during testing: {e}")
        return False


if __name__ == "__main__":
    success = test_pypi_publication()
    if success:
        print(" PyPI publication test completed successfully!")
        print(" Ready to publish with: twine upload dist/*")
    else:
        print(" PyPI publication test failed!")
        sys.exit(1)
