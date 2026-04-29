FROM python:3.12-slim

# Install iptables + iptables-persistent so rules survive across runs
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .
COPY config.yaml .

# Audit log directory
RUN mkdir -p /var/log/detector

EXPOSE 8080

CMD ["python", "-u", "main.py"]
