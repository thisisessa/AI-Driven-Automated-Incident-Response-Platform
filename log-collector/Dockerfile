FROM python:3.12-slim

WORKDIR /app

# System build tools, gcc aur OpenSSL dev headers install karein yara-python ke liye
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Root folder se requirements.txt copy karein aur install karein
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Baqi code copy karein
COPY log-collector/ .

CMD ["python3", "collector.py"]
