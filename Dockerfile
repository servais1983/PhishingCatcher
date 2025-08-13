# Dockerfile for our analysis sandbox - Secure version
FROM python:3.12-slim

# Environment variables for security
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/app

# 1. System update and security dependencies installation
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gnupg \
    wget \
    unzip \
    ca-certificates \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 2. Secure Google Chrome installation
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update && apt-get install -y \
    google-chrome-stable \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 3. Creating non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# 4. Installing necessary Python libraries with secure versions
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir selenium==4.15.0 webdriver-manager==4.0.2

# 5. Working directory configuration
WORKDIR /app

# 6. Copy our analysis script
COPY sandbox_script.py .

# 7. Changing permissions and ownership
RUN chown -R appuser:appuser /app

# 8. Switching to non-root user
USER appuser

# 9. Entry point to run the script
ENTRYPOINT ["python", "sandbox_script.py"] 