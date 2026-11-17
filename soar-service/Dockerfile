FROM apache/airflow:2.7.1-python3.10

USER root

# 1. Broken PostgreSQL repo files remove karein
RUN rm -f /etc/apt/sources.list.d/pgdg.list /etc/apt/sources.list.d/postgresql.list

# 2. Debian archive sources set karein
RUN echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security bullseye-security main" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian bullseye-updates main" >> /etc/apt/sources.list

# 3. System dependencies: gcc, libs, libmagic1 + JAVA (Spark ke liye)
RUN apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --allow-unauthenticated \
        gcc g++ libcurl4-openssl-dev libssl-dev libmagic1 \
        default-jre-headless procps curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

USER airflow

# 4. Python packages install karo (TensorFlow, PySpark, ML libs)
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /requirements.txt

# 5. PySpark ke liye Python path set karo
ENV PYSPARK_PYTHON=python3
ENV PYTHONPATH=/app:/app/ai_engine_parent:/opt/airflow:/app/dags

WORKDIR /app

# 6. Engine code copy karo
COPY engine /app/engine

# Note: ai_engine, dags, threat_simulator.py docker-compose se mount hote hain
