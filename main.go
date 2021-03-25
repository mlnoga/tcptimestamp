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


type SrcDestPair struct {
	SrcIP 		uint32
	DstIP 		uint32
	SrcPort		layers.TCPPort  // fancy uint16
	DstPort     layers.TCPPort  // fancy uint16
}

type Connection struct {
	SrcDestPair
	SynCount	uint32
}

type CaptureData struct {
	NumPackets      int32
	NumBytes        int
	CaptureStart	time.Time
	CaptureEnd      time.Time
}

type ConnData struct {
	CaptureData

	TCPTsStart      uint32
	TCPTsEnd        uint32
	MsPerTCPTs      float32
}

type ConnectionConnDataPair struct {
	Connection
	ConnData
}

// Results of the first analysis pass
type GlobalStats struct {
	CaptureData

	PacketsEthernet   int
	PacketsDot1Q      int
	PacketsIPv4       int
	PacketsIPv6       int
	PacketsTCP        int

	SynCountMap       map[SrcDestPair]uint32
	ConnDataMap 	  map[Connection]ConnData
}

// Results of the second analysis pass
type findOutliersInfo struct {
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

	fmt.Printf("Scanning trace file %s\n", *fname)

	// Main challenge: establish a basis to convert RFC 1323 TCP timestamps, which are only guaranteed
	// to be proportional to wall clock time from the capture itself, on a per connection basis 
	fmt.Printf("\nCollect start/end times\n-----------------------\n")
	p1:=collectStartEndTimes(*fname)

	duration:=p1.CaptureEnd.Sub(p1.CaptureStart)
	fmt.Printf("Capture covers time from  %v to %v (%v)\n",p1.CaptureStart, p1.CaptureEnd, duration)
    fmt.Printf("Total %d packets of size %d at %.1f packets/second\n", 
		p1.NumPackets, p1.NumBytes, float64(p1.NumPackets)/duration.Seconds())
    fmt.Printf("Thereof %d ethernet, %d Dot1Q, %d ipv4, %d ipv6 and %d tcp\n", 
		p1.PacketsEthernet, p1.PacketsDot1Q, p1.PacketsIPv4, p1.PacketsIPv6, p1.PacketsTCP)
	fmt.Printf("Found %d connections based on src/dst ip, src/dest port and syn count.\n", len(p1.ConnDataMap))

	// Build conversion table
	fmt.Printf("\nBuild TCP timestamp/ms conversions\n----------------------------------\n")
	ccdps:=make([]ConnectionConnDataPair, 0, len(p1.ConnDataMap))
	for conn,cd := range(p1.ConnDataMap) {
		ccdp:=ConnectionConnDataPair{
			Connection:conn,
			ConnData  :cd,
		}
		ccdps=append(ccdps, ccdp)
	}

	sort.Slice(ccdps, func(i, j int) bool {
		ci:=ccdps[i]
		cj:=ccdps[j]
		return ci.SrcIP<cj.SrcIP || 
		     ( ci.SrcIP==cj.SrcIP && (
               ci.SrcPort<cj.SrcPort || (
               ci.SrcPort==cj.SrcPort && (
               ci.DstIP<cj.DstIP || (
               ci.DstPort<cj.DstPort ||  (
               ci.DstPort==cj.DstPort &&
               ci.SynCount<cj.SynCount ) ) ) ) ) )  
	})

	for _,ccdp:=range(ccdps) {
		captureDuration:=ccdp.CaptureEnd.Sub(ccdp.CaptureStart)
		captureMs      :=captureDuration.Milliseconds()
		if captureMs==0 {
			captureMs=1
		}

		tcpTsDelta     :=int64(ccdp.TCPTsEnd)
		if (ccdp.TCPTsEnd<ccdp.TCPTsStart) && ((ccdp.TCPTsEnd-ccdp.TCPTsStart)<(uint32(1)<<31)) {
			tcpTsDelta+=int64(1)<<32
		}
		tcpTsDelta-=int64(ccdp.TCPTsStart)
		if tcpTsDelta==0 {
			tcpTsDelta=1
		}

		ccdp.MsPerTCPTs   =float32(float64(captureMs)/float64(tcpTsDelta))
		if ccdp.MsPerTCPTs>0 && ccdp.MsPerTCPTs<1 {
			ccdp.MsPerTCPTs=1	
		}
		if ccdp.MsPerTCPTs<0 && ccdp.MsPerTCPTs>-1 {
			ccdp.MsPerTCPTs=-1	
		}

		p1.ConnDataMap[ccdp.Connection]=ccdp.ConnData

		fmt.Printf("%3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d syn %2d: %6d packets cap start %v end %v tcpts start %9d end %d delta %7d ms %7d tcpTs %1.1f ms/tcpTs\n", 
		           ccdp.SrcIP>>24, (ccdp.SrcIP>>16) & 0xff, (ccdp.SrcIP>>8) & 0xff, ccdp.SrcIP & 0xff, ccdp.SrcPort, 
		           ccdp.DstIP>>24, (ccdp.DstIP>>16) & 0xff, (ccdp.DstIP>>8) & 0xff, ccdp.DstIP & 0xff, ccdp.DstPort, 
		           ccdp.SynCount, ccdp.NumPackets,
		           ccdp.CaptureStart, ccdp.CaptureEnd, ccdp.TCPTsStart, ccdp.TCPTsEnd,
		           captureMs, tcpTsDelta, ccdp.MsPerTCPTs)
   }

	// Run second analysis pass
	//
	fmt.Printf("\nFind Outliers\n-------------\n")
	p2:=findOutliers(*fname, p1.ConnDataMap, *threshold)

	fmt.Printf("Found %d outlier packet(s)\n", len(p2.PacketIDs))

	/*
	// sort keys by ascending packet ID
	packetIDs := make([]int, 0, len(p2.PacketIDs))
	for packetID := range p2.PacketIDs {
		packetIDs = append(packetIDs, int(packetID))
	}
	sort.Ints(packetIDs)

	for _,packetID := range(packetIDs) {
		fmt.Printf("%8d [%6dms]\n", packetID, p2.PacketIDs[int64(packetID)])
	}
	*/

	fmt.Printf("\nExiting after %v\n", time.Since(start))	
}


// The first analysis pass determines timings and the conversion factor from TCP timestamps to capture times
func collectStartEndTimes(filename string) (res GlobalStats) {
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
	res.SynCountMap=map[SrcDestPair]uint32{}
	res.ConnDataMap=map[Connection]ConnData{}

	for {
		data, ci, err := handleRead.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Fatal(err)
		} else if err == io.EOF {
			break
		} 

		// update global capture data
		if res.CaptureStart.IsZero() {
			res.CaptureStart = ci.Timestamp
		}
		res.CaptureEnd = ci.Timestamp
		res.NumPackets++
		res.NumBytes  += len(data)

		packetID++
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

		srcDestPair:=SrcDestPair{ 
			SrcIP   : ipToUInt32(ipv4.SrcIP),
			DstIP   : ipToUInt32(ipv4.DstIP),
			SrcPort : tcp.SrcPort,
			DstPort : tcp.DstPort,
		}
		synCount:=res.SynCountMap[srcDestPair]
		if tcp.SYN {
			synCount++
			res.SynCountMap[srcDestPair]=synCount
		}
		conn:=Connection{
			SrcDestPair : srcDestPair, 
			SynCount    : synCount, 
		}
		cd:=res.ConnDataMap[conn]

		// update connection capture data
		if cd.CaptureStart.IsZero() {    
			cd.CaptureStart = ci.Timestamp
		}
		cd.CaptureEnd = ci.Timestamp
		cd.NumPackets++
		cd.NumBytes  += len(data)

		// evaluate TCP timestamp if present
		for _,o:=range(tcp.Options) {
			if o.OptionType!=8 {  
				continue;
			} 
			if cd.NumPackets<=1 {
				cd.TCPTsStart=tcpTimestampToTicks(o.OptionData)
			}
			cd.TCPTsEnd=tcpTimestampToTicks(o.OptionData)
		}

		//if needForDebug==true {
		//	fmt.Printf("Packet %6d @ %6dms %6dtcpts : ", 
		//		packetID, cd.CaptureEnd.Sub(cd.CaptureStart).Milliseconds(), cd.TCPTsEnd-cd.TCPTsStart)
		//	printPacketInfo(eth, ipv4, tcp);
		//}

		res.ConnDataMap[conn]=cd;
	}		

	return res
}


// The second analysis pass finds packets whose TCP timestamps differ from the wall clock by more than the expected time
func findOutliers(filename string, connDataMap map[Connection]ConnData, thresholdMs int64) (res findOutliersInfo) {
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

	synCountMap:=map[SrcDestPair]uint32{}
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

		srcDestPair:=SrcDestPair{ 
			SrcIP   : ipToUInt32(ipv4.SrcIP),
			DstIP   : ipToUInt32(ipv4.DstIP),
			SrcPort : tcp.SrcPort,
			DstPort : tcp.DstPort,
		}
		synCount:=synCountMap[srcDestPair]
		if tcp.SYN {
			synCount++
			synCountMap[srcDestPair]=synCount
		}
		conn:=Connection{
			SrcDestPair : srcDestPair, 
			SynCount    : synCount, 
		}
		cd:=connDataMap[conn]

		var tcpTsSinceStart uint32
		var tcpMsSinceStart uint32
		var captureMsSinceStart uint32
		var deltaMs int64
		// evaluate TCP timestamp if present
		haveTCPTimestamp:=false
		for _,o:=range(tcp.Options) {
			if o.OptionType!=8 {  
				continue;
			} 
			haveTCPTimestamp=true
			// convert TCP timestamp into equivalent milliseconds since start of connection capture
			tcpTs         :=tcpTimestampToTicks(o.OptionData)
			tcpTsSinceStart=tcpTs - cd.TCPTsStart
			tcpMsSinceStart=uint32(float64(tcpTsSinceStart)*float64(cd.MsPerTCPTs))

			// convert capture timestamp into estimated milliseconds since start of connection capture
			captureMsSinceStart=uint32(ci.Timestamp.Sub(cd.CaptureStart).Milliseconds())
			deltaMs=int64(captureMsSinceStart)-int64(tcpMsSinceStart)
			if deltaMs>thresholdMs || cd.MsPerTCPTs<0 {
				res.PacketIDs[packetID]=deltaMs

				fmt.Printf("Packet %6d @ %v tcpts %9d connSince %6d ms %7d tcpms delta %7d ms: ", 
					packetID, ci.Timestamp,  tcpTs, captureMsSinceStart, tcpMsSinceStart, deltaMs)
				printPacketInfo(eth, ipv4, tcp);
			}
		}

		if !haveTCPTimestamp && cd.MsPerTCPTs<0 {
			res.PacketIDs[packetID]=999999999
			fmt.Printf("Packet %6d @ %v tcpts MISSING   connSince %6d ms MISSING tcpms delta MISSING ms: ", 
				packetID, ci.Timestamp,  ci.Timestamp.Sub(cd.CaptureStart).Milliseconds())
			printPacketInfo(eth, ipv4, tcp);
		}

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

// Converts given IP address to uint32
func ipToUInt32(ts []byte) uint32 {
	if len(ts)!=4 {
		return 0
	}
	return (uint32(ts[0])<<24) | (uint32(ts[1])<<16) | (uint32(ts[2])<<8) | (uint32(ts[3])<<0)  
}


func printPacketInfo(eth layers.Ethernet, ipv4 layers.IPv4, tcp layers.TCP) {
	fmt.Printf("[%v] %v:%v -> ", eth.SrcMAC, ipv4.SrcIP, tcp.SrcPort)
	fmt.Printf("%v:%v [%v]", ipv4.DstIP, tcp.DstPort, eth.DstMAC)
	fmt.Printf(" Seq %d Flags", tcp.Seq)
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
