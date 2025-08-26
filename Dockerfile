FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep (optional, for SAST scanning)
RUN python -m pip install --upgrade pip \
    && pip install semgrep

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create output directory
RUN mkdir -p /app/output /app/logs /app/logs/prompts

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash analyzer
RUN chown -R analyzer:analyzer /app
USER analyzer

# Expose port (if needed for future web interface)
EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["python", "main.py"]

# Default command shows help
CMD ["--help"]
