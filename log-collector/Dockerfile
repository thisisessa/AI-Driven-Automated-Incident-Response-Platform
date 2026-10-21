FROM python:3.10-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY collector.py .
CMD ["python", "-u", "collector.py"]
