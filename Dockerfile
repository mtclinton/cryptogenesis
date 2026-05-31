FROM python:3.11-slim

# Force unbuffered output for Docker logs
ENV PYTHONUNBUFFERED=1
# Enable test mode with easier mining difficulty
ENV TEST_MODE=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY cryptogenesis/ ./cryptogenesis/
COPY setup.py .
COPY README.md .
RUN pip install -e .


# Copy visualization server
COPY visualization_server.py .
COPY static/ ./static/

# Default command (use -u for unbuffered output)
CMD ["python", "-u", "-m", "cryptogenesis.node"]
