package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var (
	host       string
	prefixFile string
	pcapFile   string
	debug      bool
)

func init() {
	// Parse command line arguments
	flag.BoolVarP(&debug, "verbose", "v", false, "Enable debug logging")
	flag.StringVarP(&prefixFile, "prefixFile", "p", "", "IP prefixes to match")
	flag.StringVarP(&pcapFile, "pcapFile", "f", "", "PCAP file to process")
	flag.Parse()

	if debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug logging enabled")
	}

	if prefixFile == "" {
		log.Fatalf("A prefix file is required")
	}

	if pcapFile == "" {
		log.Fatalf("A pcap is required")
	}

	log.Debugf("Using prefix file %v\n", prefixFile)

	host = strings.Split(pcapFile, "-")[0]

}

func main() {

	fileTime := strings.Join(strings.Split(strings.Split(pcapFile, ".")[0], "-")[2:], "-")
	layout := "2006-01-02_15-04-05"
	t, err := time.Parse(layout, fileTime)
	if err != nil {
		log.Fatal(err)
	}
	rfc3339Str := t.Format(time.RFC3339)

	// Create a v4 and v6 prefix trie
	var v4_trie = ipaddr.Trie[*ipaddr.IPAddress]{}
	var v6_trie = ipaddr.Trie[*ipaddr.IPAddress]{}

	f, err := os.Open(prefixFile)
	if err != nil {
		log.Fatalf("Error opening prefix file %v: %v", prefixFile, err)
	}
	defer f.Close()

	// Create a map to track which IPs we've seen this interval
	hitMap := make(map[string]interface{})

	// Build a v6/v4 prefix trie
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		addr := ipaddr.NewIPAddressString(scanner.Text()).GetAddress()

		// Create the dictionary for this prefix
		hitMap[addr.String()] = make(map[string]uint)

		if addr.IsIPv4() {
			v4_trie.Add(addr)
		} else if addr.IsIPv6() {
			v6_trie.Add(addr)
		}
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		networkLayer := packet.NetworkLayer()
		if networkLayer != nil {
			switch networkLayer.LayerType() {
			case layers.LayerTypeIPv4:
				ip4 := networkLayer.(*layers.IPv4)
				addr := ipaddr.NewIPAddressString(ip4.SrcIP.String()).GetAddress()
				// Check if the IP is in the trie
				result := v4_trie.LongestPrefixMatch(addr)

				if result != nil {
					hitMap[result.String()].(map[string]uint)[addr.String()]++
				}

			case layers.LayerTypeIPv6:
				ip6 := networkLayer.(*layers.IPv6)
				addr := ipaddr.NewIPAddressString(ip6.SrcIP.String()).GetAddress()
				// Check if the IP is in the trie
				result := v6_trie.LongestPrefixMatch(addr)
				if result != nil {
					hitMap[result.String()].(map[string]uint)[addr.String()]++
				}
			}
		}
	}

	hitMap["vp"] = host
	hitMap["timestamp"] = rfc3339Str

	jsonData, err := json.Marshal(hitMap)
	if err != nil {
		log.Fatal("Error:", err)
	}

	outfileName := fmt.Sprintf("%v-ntp-hits-%v.json", host, fileTime)

	// Write base64 string to a file
	file, err := os.Create(outfileName)
	if err != nil {
		log.Fatalln("Error creating file:", err)
	}
	defer file.Close()

	_, err = file.WriteString(string(jsonData))
	if err != nil {
		log.Fatalln("Error writing to file:", err)
	}

	log.Infoln("Results written to", outfileName)

}
