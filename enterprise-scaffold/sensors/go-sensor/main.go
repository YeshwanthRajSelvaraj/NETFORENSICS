// NetForensics Edge Sensor
// A lightweight, high-performance packet capture agent written in Go using AF_PACKET.
// Captures network traffic, extracts L3/L4 metadata, and streams to the Ingestion Gateway.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/afpacket"
)

// Config parameters
var (
	iface         = flag.String("interface", "eth0", "Interface to read packets from")
	ingestURL     = flag.String("url", "http://localhost:8080/api/v1/ingest/packets", "Ingestion Gateway URL")
	tenantToken   = flag.String("token", "", "Bearer token for tenant authentication")
	sensorID      = flag.String("sensor", "sensor-go-01", "Unique identifier for this edge node")
	batchSize     = flag.Int("batch", 100, "Number of packets to batch before sending")
	flushInterval = flag.Duration("flush", 5*time.Second, "Max time to wait before flushing batch")
	debug         = flag.Bool("debug", false, "Enable verbose logging")
)

// PacketMetadata matches the Python Pydantic schema in the Ingestion Gateway
type PacketMetadata struct {
	Timestamp      float64 `json:"timestamp"`
	SrcIP          string  `json:"src_ip"`
	DstIP          string  `json:"dst_ip"`
	SrcPort        int     `json:"src_port"`
	DstPort        int     `json:"dst_port"`
	Protocol       string  `json:"protocol"`
	Size           int     `json:"size"`
	TCPFlags       string  `json:"tcp_flags,omitempty"`
	PayloadEntropy float64 `json:"payload_entropy,omitempty"`
}

// IngestRequest represents the batch payload
type IngestRequest struct {
	SensorID string           `json:"sensor_id"`
	Events   []PacketMetadata `json:"events"`
}

type PacketBatcher struct {
	mu     sync.Mutex
	events []PacketMetadata
	client *http.Client
}

func NewBatcher() *PacketBatcher {
	return &PacketBatcher{
		events: make([]PacketMetadata, 0, *batchSize),
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (b *PacketBatcher) Add(event PacketMetadata) {
	b.mu.Lock()
	b.events = append(b.events, event)
	count := len(b.events)
	b.mu.Unlock()

	if count >= *batchSize {
		go b.Flush()
	}
}

func (b *PacketBatcher) Flush() {
	b.mu.Lock()
	if len(b.events) == 0 {
		b.mu.Unlock()
		return
	}
	
	// Create a copy to send, clear the buffer
	eventsToSend := make([]PacketMetadata, len(b.events))
	copy(eventsToSend, b.events)
	b.events = b.events[:0]
	b.mu.Unlock()

	reqPayload := IngestRequest{
		SensorID: *sensorID,
		Events:   eventsToSend,
	}

	jsonData, err := json.Marshal(reqPayload)
	if err != nil {
		log.Printf("Error marshalling JSON: %v", err)
		return
	}

	req, err := http.NewRequest("POST", *ingestURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating HTTP request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if *tenantToken != "" {
		req.Header.Set("Authorization", "Bearer "+*tenantToken)
	}

	start := time.Now()
	resp, err := b.client.Do(req)
	
	if err != nil {
		log.Printf("Failed to push batch to ingestion gateway: %v", err)
		return
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("Pushed %d packets to %s in %v (Status: %s)", len(eventsToSend), *ingestURL, time.Since(start), resp.Status)
	}
}

func main() {
	flag.Parse()

	if *tenantToken == "" {
		log.Fatal("Must provide a tenant --token for authentication")
	}

	log.Printf("Starting NetForensics Go Sensor on interface %s", *iface)
	log.Printf("Sensor ID: %s | Ingest URL: %s", *sensorID, *ingestURL)

	// Setup AF_PACKET (Zero-copy, extremely fast packet capture for Linux)
	// Fallback to standard pcap could be added for Windows/Mac support.
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(*iface),
		afpacket.OptFrameSize(2048),
		afpacket.OptBlockSize(2048*128), // 256KB blocks
		afpacket.OptNumBlocks(256),      // 64MB buffer
	)
	if err != nil {
		log.Fatalf("Failed to start AF_PACKET (Are you root? Is interface correct?): %v", err)
	}
	defer tpacket.Close()

	source := gopacket.NewPacketSource(tpacket, layers.LinkTypeEthernet)
	
	// Fast decoding options
	source.DecodeOptions = gopacket.DecodeOptions{
		Lazy: true,
		NoCopy: true,
	}

	batcher := NewBatcher()

	// Background routine to flush incomplete batches periodically
	go func() {
		ticker := time.NewTicker(*flushInterval)
		for range ticker.C {
			batcher.Flush()
		}
	}()

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		log.Println("Shutting down sensor. Flushing final batch...")
		batcher.Flush()
		os.Exit(0)
	}()

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var icmp layers.ICMPv4
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &tcp, &udp, &icmp,
	)
	decoded := []gopacket.LayerType{}

	log.Println("Capture started successfully. Listening...")

	packetCount := 0
	for {
		data, _, err := tpacket.ZeroCopyReadPacketData()
		if err != nil {
			log.Printf("Error reading packet data: %v", err)
			continue
		}

		err = parser.DecodeLayers(data, &decoded)
		if err != nil && err != gopacket.UnsupportedLayerType {
			// Ignore unsupported types, just process what we successfully decoded
		}

		meta := PacketMetadata{
			Timestamp: float64(time.Now().UnixNano()) / 1e9,
			Size:      len(data),
		}

		validIP := false
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				meta.SrcIP = ip4.SrcIP.String()
				meta.DstIP = ip4.DstIP.String()
				validIP = true
			case layers.LayerTypeIPv6:
				meta.SrcIP = ip6.SrcIP.String()
				meta.DstIP = ip6.DstIP.String()
				validIP = true
			case layers.LayerTypeTCP:
				meta.Protocol = "TCP"
				meta.SrcPort = int(tcp.SrcPort)
				meta.DstPort = int(tcp.DstPort)
				
				flags := ""
				if tcp.SYN { flags += "S" }
				if tcp.ACK { flags += "A" }
				if tcp.FIN { flags += "F" }
				if tcp.RST { flags += "R" }
				if tcp.PSH { flags += "P" }
				meta.TCPFlags = flags
				
				// Payload entropy could be calculated here for ML features
				// meta.PayloadEntropy = calculateEntropy(tcp.Payload)
			case layers.LayerTypeUDP:
				meta.Protocol = "UDP"
				meta.SrcPort = int(udp.SrcPort)
				meta.DstPort = int(udp.DstPort)
			case layers.LayerTypeICMPv4:
				meta.Protocol = "ICMP"
			}
		}

		if validIP && meta.Protocol != "" {
			batcher.Add(meta)
			packetCount++
		}
	}
}
