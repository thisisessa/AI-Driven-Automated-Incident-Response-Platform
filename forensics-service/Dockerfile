FROM python:3.10-slim

# Install system tools: ClamAV, Sleuthkit, YARA, aur C-Compiler (gcc) for yara-python
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    sleuthkit \
    yara \
    git \
    gcc \
    build-essential \
    libyara-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# Yahan gcc install hone ke baad pip install successfully chalega
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port for FastAPI
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
