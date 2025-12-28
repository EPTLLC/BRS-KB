FROM python:3.10-slim

LABEL maintainer="EasyProTech LLC <contact@easyprotech>"
LABEL version="4.0.0"
LABEL description="BRS-KB XSS Intelligence Platform"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
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
