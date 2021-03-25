// Copyright 2021 Markus Noga of SUSE. All rights reserved.
//
// This program loads package capture files and detects packets
// whose TCP timestamp in ticks and capture timestamps in wall clock time
// differ by more than a given threshold. It does this focused on one host

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)


var fname     = flag.String("r", "", "Filename to read the pcap network capture from")
var srcip     = flag.String("i", "", "Source IP address to filter for")
var threshold = flag.Int64("t", 2000, "Theshold in ms for max acceptable difference between capture and TCP timestamps")


// Results of the first analysis pass
type Pass1Info struct {
	Start             time.Time
	End               time.Time
	PacketsTotal      int
	SizeTotal         int

	PacketsEthernet   int
	PacketsDot1Q      int
	PacketsIPv4       int
	PacketsIPv6       int
	PacketsTCP        int
	PacketsTCP2       int

	PacketsFromSource int

	SourceStart       time.Time
	SourceEnd         time.Time

	SourceTSStart     []byte
	SourceTSEnd       []byte

	SourceMACs		  map[string]bool
}


// Results of the second analysis pass
type Pass2Info struct {
	PacketIDs         map[int64]int64
}


func main() {
	start := time.Now()
	defer util.Run()()

	// Sanity checks
	if *fname == "" {
		log.Fatal("Need a input file")
	}

	// Open PCAP file + handle potential BPF Filter
	handleRead, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}
	defer handleRead.Close()
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		fmt.Fprintf(os.Stderr, "Using BPF filter %q\n", bpffilter)
		if err = handleRead.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	}

	sourceIP:=net.ParseIP(*srcip)
	fmt.Printf("Scanning trace file %s for source IP %v\n", *fname, sourceIP)

	// Run first analysis pass
	// Main challenge: establish a basis to convert RFC 1323 TCP timestamps, which are only guaranteed
	// to be proportional to wall clock time from the capture itself 
	fmt.Printf("\nPass 1\n------\n")
	p1:=pass1(*fname, sourceIP)

	duration:=p1.End.Sub(p1.Start)
	fmt.Printf("Capture covers time from  %v to %v (%v)\n",p1.Start, p1.End, duration)
    fmt.Printf("Total %d packets of size %d at %.1f packets/second\n", 
		p1.PacketsTotal, p1.SizeTotal, float64(p1.PacketsTotal)/duration.Seconds())
    fmt.Printf("Thereof %d ethernet, %d Dot1Q, %d ipv4, %d ipv6 and %d / %d tcp\n", 
		p1.PacketsEthernet, p1.PacketsDot1Q, p1.PacketsIPv4, p1.PacketsIPv6, p1.PacketsTCP, p1.PacketsTCP2)

	sourceDuration:=p1.SourceEnd.Sub(p1.SourceStart)
	sourceDurationMS:=sourceDuration.Milliseconds()
	fmt.Printf("\n%d packets from source IP %v\n", p1.PacketsFromSource, sourceIP)
	fmt.Printf("They cover the time from  %v to %v (%v)\n",p1.SourceStart, p1.SourceEnd, sourceDuration)

	tickStart:=tcpTimestampToTicks(p1.SourceTSStart)
	tickEnd  :=tcpTimestampToTicks(p1.SourceTSEnd)
	tickDelta:=tickEnd-tickStart
	fmt.Printf("The corresponding TCP timestamps range from %d to %d (%d ticks)\n", 
		 		tickStart, tickEnd, tickDelta)
	ticksPerMS:=float64(tickDelta)/float64(sourceDurationMS)
	fmt.Printf("Resulting conversion factor is %.3f ticks/ms\n", ticksPerMS)

	fmt.Printf("Source MACs are")
	for macString:=range p1.SourceMACs {
		mac:=net.HardwareAddr([]byte(macString))
		fmt.Printf(" %s", mac)
	}
	fmt.Printf("\n")

	// Run second analysis pass
	//
	fmt.Printf("\nPass 2\n------\n")
	p2:=pass2(*fname, sourceIP, p1.SourceStart, tickStart, ticksPerMS, *threshold)

	fmt.Printf("Found %d outlier packet(s). Packet numbers and corresponding delays in ms are:\n", len(p2.PacketIDs))

	// sort keys by ascending packet ID
	packetIDs := make([]int, 0, len(p2.PacketIDs))
	for packetID := range p2.PacketIDs {
		packetIDs = append(packetIDs, int(packetID))
	}
	sort.Ints(packetIDs)

	for _,packetID := range(packetIDs) {
		fmt.Printf("%8d [%6dms]\n", packetID, p2.PacketIDs[int64(packetID)])
	}

	fmt.Printf("\nExiting after %v\n", time.Since(start))	
}


// The first analysis pass determines timings and the conversion factor from TCP timestamps to capture times
func pass1(filename string, sourceIP net.IP) (res Pass1Info) {
	handleRead, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var payload gopacket.Payload

	parser  := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ipv4, &ipv6, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	res.SourceMACs=map[string]bool{}

	for {
		data, ci, err := handleRead.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Fatal(err)
		} else if err == io.EOF {
			break
		} 

		if res.Start.IsZero() {
			res.Start = ci.Timestamp
		}
		res.End = ci.Timestamp
		res.PacketsTotal++
		res.SizeTotal   += len(data)

		if err := parser.DecodeLayers(data, &decoded); err != nil {

			//fmt.Fprintf(os.Stderr, "Could not decode layer: %v\n", err)
			continue
		}

		var haveEthernet, haveIPv4, haveTCP bool
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				res.PacketsEthernet++
				haveEthernet=true
			case layers.LayerTypeDot1Q:
				res.PacketsDot1Q++					
			case layers.LayerTypeIPv4:
				res.PacketsIPv4++
				haveIPv4=true
			case layers.LayerTypeIPv6:
				res.PacketsIPv6++
			case layers.LayerTypeTCP:
			  	res.PacketsTCP++
			  	haveTCP=true
			default: // Ignore payload
			}
		}

		if !haveEthernet || !haveIPv4 || !haveTCP {  // keep valid packets only
			continue
		}

		if !ipv4.SrcIP.Equal(sourceIP) { // focus on given source IP
			continue
		}
		res.PacketsFromSource++

		if res.SourceStart.IsZero() {    // keep track of capture start/end time
			res.SourceStart = ci.Timestamp
		}
		res.SourceEnd = ci.Timestamp

		for _,o:=range(tcp.Options) {
			if o.OptionType!=8 {  // throw away all but the timestamp
				continue;
			} 
			if res.SourceTSStart==nil {
				res.SourceTSStart=o.OptionData
			}
			res.SourceTSEnd=o.OptionData
		}

		macString:=string(eth.SrcMAC)    // keep track of the set of MACs used
		res.SourceMACs[macString]=true;
	}		

	return res
}


// The second analysis pass finds packets whose TCP timestamps differ from the wall clock by more than the expected time
func pass2(filename string, sourceIP net.IP, startTime time.Time, tickStart uint32, ticksPerMS float64, thresholdMs int64) (res Pass2Info) {
	handleRead, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var payload gopacket.Payload

	parser  := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ipv4, &ipv6, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	var packetID int64=-1
	res.PacketIDs=map[int64]int64{}

	for {
		data, ci, err := handleRead.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Fatal(err)
		} else if err == io.EOF {
			break
		} 
		
		packetID++
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			//fmt.Fprintf(os.Stderr, "Could not decode layer: %v\n", err)
			continue
		}

		var haveEthernet, haveIPv4, haveTCP bool
		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeEthernet:
				haveEthernet=true
			case layers.LayerTypeDot1Q:
			case layers.LayerTypeIPv4:
				haveIPv4=true
			case layers.LayerTypeIPv6:
			case layers.LayerTypeTCP:
			  	haveTCP=true
			default: // Ignore payload
			}
		}

		if !haveEthernet || !haveIPv4 || !haveTCP {  // keep valid packets only
			continue
		}

		if !ipv4.SrcIP.Equal(sourceIP) { // focus on given source IP
			continue
		}

		var captureMs int64
		var ticksElapsed uint32
		var tcpMs, deltaMs int64
		for _,o:=range(tcp.Options) {
			if o.OptionType!=8 {  // throw away all but the timestamp
				continue;
			} 

			// convert capture timestamp into estimated milliseconds since start of capture
			captureMs=ci.Timestamp.Sub(startTime).Milliseconds()
			// convert TCP timestamp into estimated milliseconds since start of capture
			ticks:=tcpTimestampToTicks(o.OptionData)
			ticksElapsed=ticks-tickStart
			tcpMs=int64(float64(ticksElapsed)/ticksPerMS)

			deltaMs=int64(captureMs-tcpMs)
			if deltaMs>thresholdMs {
				res.PacketIDs[packetID]=deltaMs
			}
		}
		fmt.Printf("P%6d @ c%6d tcp%6d tcpms%6d delta%6d: ", packetID, captureMs, ticksElapsed, tcpMs, deltaMs)
		printPacketInfo(eth, ipv4, tcp);
	}		

	return res
}

// Converts given TCP timestamp to uncalibrated ticks
func tcpTimestampToTicks(ts []byte) uint32 {
	if len(ts)!=8 {
		return 0
	}
	return (uint32(ts[0])<<24) | (uint32(ts[1])<<16) | (uint32(ts[2])<<8) | (uint32(ts[3])<<0)  
}


func printPacketInfo(eth layers.Ethernet, ipv4 layers.IPv4, tcp layers.TCP) {
	fmt.Printf("MAC %v IP %v : %v -> ", eth.SrcMAC, ipv4.SrcIP, tcp.SrcPort)
	fmt.Printf("MAC %v IP %v : %v ", eth.DstMAC, ipv4.DstIP, tcp.DstPort)
	fmt.Printf("Flags")
	if(tcp.FIN) { fmt.Printf(" FIN") }
	if(tcp.SYN) { fmt.Printf(" SYN") }
	if(tcp.RST) { fmt.Printf(" RST") }
	if(tcp.PSH) { fmt.Printf(" PSH") }
	if(tcp.ACK) { fmt.Printf(" ACK") }
	if(tcp.URG) { fmt.Printf(" URG") }
	if(tcp.ECE) { fmt.Printf(" ECE") }
	if(tcp.CWR) { fmt.Printf(" CWR") }
	if(tcp.NS)  { fmt.Printf(" NS")  }
	fmt.Printf("\n")
}
