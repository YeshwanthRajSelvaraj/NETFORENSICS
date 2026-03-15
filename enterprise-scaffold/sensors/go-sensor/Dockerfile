// Build stage
FROM golang:1.20-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download

# Required for compiling gopacket CGO dependencies
RUN apk add --no-cache gcc libc-dev libpcap-dev

COPY main.go ./

# Build statically linked binary allowing execution on minimal distros
RUN CGO_ENABLED=1 go build -ldflags="-extldflags=-static" -o nf-sensor main.go

// Deployment stage
FROM alpine:latest
RUN apk add --no-cache libpcap

WORKDIR /root/
COPY --from=builder /app/nf-sensor .

ENTRYPOINT ["./nf-sensor"]
CMD ["-interface", "eth0", "-url", "http://ingestion-service:8080/api/v1/ingest/packets"]
