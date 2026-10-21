FROM python:3.10-slim
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY misp_server.py .
EXPOSE 80
CMD ["python", "-u", "misp_server.py"]
