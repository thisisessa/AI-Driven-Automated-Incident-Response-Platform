FROM python:3.12-slim

WORKDIR /app

# Added default-jre-headless (for Java/Spark) and procps (for ps command)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    pkg-config \
    libssl-dev \
    libffi-dev \
    libmagic1 \
    libyara-dev \
    default-jre-headless \
    procps \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

COPY ai_engine/ ./ai_engine/
COPY log-collector/ .

# Set environment variables for PySpark
ENV PYSPARK_PYTHON=python3
ENV PYTHONPATH=/app

CMD ["python3", "collector.py"]
