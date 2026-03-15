FROM python:3.11-slim

WORKDIR /app

# Install build dependencies for compiling Faust/C extensions (e.g., cchardet)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Keep Faust memory maps in a specific directory
ENV FAUST_DATADIR=/var/lib/faust

# Ensure Kafka broker can be configured
ENV KAFKA_BROKER="kafka://kafka:9092"

CMD ["faust", "-A", "main_worker", "worker", "-l", "info", "--web-port", "6066"]
