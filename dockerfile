FROM python:3.12-slim

# Allow ICMP ping
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ ./templates/

# Persistent DB folder
RUN mkdir -p /app/db

EXPOSE 5000

CMD ["python", "app.py"]