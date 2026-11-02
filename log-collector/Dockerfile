FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    pkg-config \
    libssl-dev \
    libffi-dev \
    libmagic1 \
    libyara-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

COPY ai_engine/ ./ai_engine/
COPY log-collector/ .

CMD ["python3", "collector.py"]
