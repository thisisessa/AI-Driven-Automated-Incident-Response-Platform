FROM apache/airflow:2.7.1-python3.10

USER root

# 1. Broken PostgreSQL repo files remove karein
RUN rm -f /etc/apt/sources.list.d/pgdg.list /etc/apt/sources.list.d/postgresql.list

# 2. Debian archive sources set karein
RUN echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security bullseye-security main" >> /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian bullseye-updates main" >> /etc/apt/sources.list

# 3. Update aur libmagic1 ke sath required packages install karein
RUN apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --allow-unauthenticated gcc g++ libcurl4-openssl-dev libssl-dev libmagic1

USER airflow
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

WORKDIR /app
COPY engine /app/engine
