FROM python:3.9-slim

# Install basic system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data directory and set permissions
RUN mkdir -p /app/data && \
    chmod 755 /app/data

# Expose port (will be overridden in docker-compose)
EXPOSE 18333

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from cryptogenesis.services import get_services; services = get_services(); print('OK')" || exit 1

# Set entrypoint
ENTRYPOINT ["python", "main.py"]
