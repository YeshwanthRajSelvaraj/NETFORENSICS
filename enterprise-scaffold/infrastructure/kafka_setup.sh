#!/bin/bash
# Sets up Kafka Topics for the NetForensics Enterprise Platform.
# Run this inside the Kafka Docker container or from an environment with kafka-topics.sh

BROKER="kafka:9092"
PARTITIONS=3
REPLICATION=1  # Set to 3 in production

echo "Creating core NetForensics Kafka topics..."

topics=(
    "nf.raw_packets"
    "nf.flows"
    "nf.tls"
    "nf.dns"
    "nf.alerts"
)

for topic in "${topics[@]}"; do
    echo "Creating topic: $topic"
    kafka-topics \
        --bootstrap-server $BROKER \
        --create \
        --if-not-exists \
        --topic "$topic" \
        --partitions $PARTITIONS \
        --replication-factor $REPLICATION \
        --config retention.ms=86400000 \
        --config compression.type=zstd
    
    # 86400000 ms = 24 hours retention in the broker. 
    # Elasticsearch is long-term storage, Kafka is just the buffer.
done

echo "Topic creation complete."
kafka-topics --bootstrap-server $BROKER --list
