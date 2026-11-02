FROM python:3.12-slim

WORKDIR /app

# Install system dependencies required by Python and YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    pkg-config \
    libssl-dev \
    libffi-dev \
    libmagic1 \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies
COPY requirements.txt .

# Install Python packages
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Copy AI Engine source code
COPY ai_engine/ ./ai_engine/

CMD ["python3", "ai_engine/spark_processor.py"]
