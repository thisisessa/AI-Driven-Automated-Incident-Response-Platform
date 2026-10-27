FROM python:3.10-slim

WORKDIR /app


RUN pip install --no-cache-dir requests numpy pandas scikit-learn


COPY . /app/

CMD ["python", "-u", "collector.py"]
