package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/seancfoley/ipaddress-go/ipaddr"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
)

var (
	v4Queue    uint16
	v6Queue    uint16
	prefixFile string
	tick       int
	debug      bool
	ticker     *time.Ticker
	mu         sync.Mutex
	host       string
)

func init() {
	// Parse command line arguments
	flag.StringVarP(&host, "host", "H", "", "Host name for file output")
	flag.IntVarP(&tick, "time", "t", 3600, "Time to write prefix hits")
	flag.BoolVarP(&debug, "verbose", "v", false, "Enable debug logging")
	flag.StringVarP(&prefixFile, "prefixFile", "p", "", "IP prefixes to match")
	flag.Uint16VarP(&v4Queue, "v4Queue", "4", 200, "IPv4 NFQUEUE queue number")
	flag.Uint16VarP(&v6Queue, "v6Queue", "6", 100, "IPv6 NFQUEUE queue number")
	flag.Parse()

	if debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug logging enabled")
	}

	if prefixFile == "" {
		log.Fatalf("A prefix files is required")
	}

	if host == "" {
		log.Fatalf("A host name is required")
	}

	log.Debugf("Using prefix file %v\n", prefixFile)

	//
	ticker = time.NewTicker(time.Duration(tick) * time.Second)

	log.Debugf("Writing results every %v seconds\n", tick)

}

func main() {

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

	// Write the results every -t seconds to a new JSON object
	go func() {
		for range ticker.C {
			log.Println("[*] Ticker ticking; writing JSON")
			mu.Lock()

			currentTime := time.Now()

			hitMap["timestamp"] = currentTime.Format(time.RFC3339)
			hitMap["vp"] = host

			jsonData, err := json.Marshal(hitMap)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			// Format the current time as "YYYY-MM-DD-HH-MM"
			formattedDate := currentTime.Format("2006-01-02-15-04")

			outfileName := fmt.Sprintf("prefix-hits-%v-%v.json", host, formattedDate)

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

			// Clear out each of the sub-maps
			for k := range hitMap {
				hitMap[k] = make(map[string]uint)
			}
			mu.Unlock()
		}
	}()

	// Set configuration options for the IPv4 nfqueue
	v4config := nfqueue.Config{
		NfQueue:      v4Queue,
		MaxPacketLen: 0xFFFFFF,
		MaxQueueLen:  0xFFFFFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	// Set configuration options for the IPv6 nfqueue
	v6config := nfqueue.Config{
		NfQueue:      v6Queue,
		MaxPacketLen: 0xFFFFFF,
		MaxQueueLen:  0xFFFFFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf4, err := nfqueue.Open(&v4config)
	if err != nil {
		log.Fatalln("could not open nfqueue socket:", err)
		return
	}
	defer nf4.Close()

	nf6, err := nfqueue.Open(&v6config)
	if err != nil {
		log.Fatalln("could not open nfqueue socket:", err)
		return
	}
	defer nf6.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//Callback for successful NFQUEUE packet
	fn4 := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		ntpPkt := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4,
			gopacket.Default)

		//Pull out src IP
		srcIP, _ := ntpPkt.NetworkLayer().NetworkFlow().Endpoints()

		//fmt.Println("Src IP: ", srcIP)

		// Result of trie lookup
		var result *ipaddr.IPAddress

		// Convert to ipaddr IP address
		addr := ipaddr.NewIPAddressString(srcIP.String()).GetAddress()

		result = v4_trie.LongestPrefixMatch(addr)
		if result != nil {
			log.Infof("Found %v in result %v in v4 trie", addr, result)
			mu.Lock()
			hitMap[result.String()].(map[string]uint)[addr.String()]++
			mu.Unlock()
		}
		nf4.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	errfn := func(e error) int {
		log.Println("Received error: ", e)
		return 0
	}

	//Callback for successful IPv6 NFQUEUE packet
	fn6 := func(a nfqueue.Attribute) int {
		id := *a.PacketID
		ntpPkt := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv6,
			gopacket.Default)

		//Pull out src IP
		srcIP, _ := ntpPkt.NetworkLayer().NetworkFlow().Endpoints()

		//fmt.Println("Src IP: ", srcIP)

		// Result of trie lookup
		var result *ipaddr.IPAddress

		// Convert to ipaddr IP address
		addr := ipaddr.NewIPAddressString(srcIP.String()).GetAddress()

		result = v6_trie.LongestPrefixMatch(addr)
		if result != nil {
			log.Infof("Found %v in result %v in v6 trie", addr, result)
			mu.Lock()
			hitMap[result.String()].(map[string]uint)[addr.String()]++
			mu.Unlock()
		}

		nf6.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	// Register your function to listen on the IPv4 nfqueue
	err = nf4.RegisterWithErrorFunc(ctx, fn4, errfn)
	if err != nil {
		log.Println(err)
		return
	}

	// Register your function to listen on the nfqueue
	err = nf6.RegisterWithErrorFunc(ctx, fn6, errfn)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println("[+] Running until Ctrl-C pressed")
	// Block till the context expires
	<-ctx.Done()

}
