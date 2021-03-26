// Copyright 2021 Markus Noga of SUSE. All rights reserved.
//
// This program loads package capture files and detects packets
// whose TCP timestamp in ticks and capture timestamps in wall clock time
// differ by more than a given threshold. It does this focused on one host

package main

import (
	"flag"
	"io"
	"log"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
)


var readFileName          = flag.String("r", "",    "Filename for input PCAP file")
var writeFileName         = flag.String("w", "",    "Filename for output analysis file. Overrides potential filename generation")
var generateWriteFileName = flag.Bool  ("g", false, "Generate output file by appending .analysis to the input filename")
var threshold             = flag.Int64 ("t", 5000,  "Theshold in ms for max acceptable difference between capture and TCP timestamps")


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
	MsPerTCPTs      float32      // conversion factor. contains sum during initial data gathering
	MsPerTCPTsCount int32        // during initial data gathering, contains divider which turns sum into average
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
	PacketIDs         map[uint64]int64
}


func main() {
	start := time.Now()
	flag.Parse()
	log.SetFlags(0)

	// redirect output to file if required
	theWriteFileName:=*writeFileName
	if theWriteFileName=="" && *generateWriteFileName {
		theWriteFileName=*readFileName + ".analysis"
	}
	if theWriteFileName!="" {
		writer, err:=os.Create(theWriteFileName)
		if err!=nil {
			log.Fatalf("Error opening output file %s: %s", theWriteFileName, err)
		}		
		log.SetOutput(writer)
		flag.CommandLine.SetOutput(writer)
	}

	// Sanity checks
	if *readFileName == "" {
		log.Printf("Usage: tcptimestamps [-flags]")
		flag.PrintDefaults();
		log.Fatal("Fatal: Need an input file")
	}

	// Open PCAP file
	log.Printf("Scanning trace file %s\n", *readFileName)

	// Main challenge: establish a basis to convert RFC 1323 TCP timestamps, which are only guaranteed
	// to be proportional to wall clock time from the capture itself, on a per connection basis 
	log.Printf("\nCollect start/end times\n-----------------------\n")
	p1:=collectStartEndTimes(*readFileName)

	duration:=p1.CaptureEnd.Sub(p1.CaptureStart)
	log.Printf("Capture covers time from  %v to %v (%v)\n",p1.CaptureStart, p1.CaptureEnd, duration)
    log.Printf("Total %d packets of size %d at %.1f packets/second\n", 
		p1.NumPackets, p1.NumBytes, float64(p1.NumPackets)/duration.Seconds())
    log.Printf("Thereof %d ethernet, %d Dot1Q, %d ipv4, %d ipv6 and %d tcp\n", 
		p1.PacketsEthernet, p1.PacketsDot1Q, p1.PacketsIPv4, p1.PacketsIPv6, p1.PacketsTCP)
	log.Printf("Found %d connections based on src/dst ip, src/dest port and syn count.\n", len(p1.ConnDataMap))

	// Build conversion table
	log.Printf("\nBuild TCP timestamp/ms conversions\n----------------------------------\n")
	buildTimestampConversionTable(p1.ConnDataMap)

	// Find outliers
	log.Printf("\nFind Outliers\n-------------\n")
	p2:=findOutliers(*readFileName, p1.ConnDataMap, *threshold)
	log.Printf("Total %d outlier packets (%f%% of TCP packets).\n", len(p2.PacketIDs), float64(len(p2.PacketIDs))*100.0/float64(p1.PacketsTCP))

	log.Printf("\nExiting after %v\n", time.Since(start).Truncate(100*time.Millisecond))	
}


// Find connections and collect wall clock and TCP timestamp start and end times per connection
func collectStartEndTimes(fileName string) (res GlobalStats) {
	handleRead, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal("Error opening PCAP file:", err)
	}
	defer handleRead.Close()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var payload gopacket.Payload

	parser  := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ipv4, &ipv6, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	var packetID int64=0
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
		haveTCPTimestamp:=false
		for _,o:=range(tcp.Options) {
			if o.OptionType!=8 {  
				continue;
			} 
			if cd.NumPackets<=1 {
				cd.TCPTsStart=tcpTimestampFromBytes(o.OptionData)
			}
			cd.TCPTsEnd=tcpTimestampFromBytes(o.OptionData)
			haveTCPTimestamp=true;
		}

		if(haveTCPTimestamp) {
			// calculate conversion factor 
			captureDuration:=ci.Timestamp.Sub(cd.CaptureStart)
			captureMs      :=timeDurationToMilliseconds(captureDuration)
			if captureMs==0 {
				captureMs=1
			}

			tcpTsDelta     :=tcpTimestampDelta(cd.TCPTsStart, cd.TCPTsEnd)
			if tcpTsDelta==0 {
				tcpTsDelta=1
			}

			thisMsPerTCPTs:=float32(float64(captureMs)/float64(tcpTsDelta))

			// update running average for this connection
			cd.MsPerTCPTs+=thisMsPerTCPTs
			cd.MsPerTCPTsCount++
		}

		//if needForDebug==true {
		//	log.Printf("Packet %6d @ %6dms %6dtcpts : ", 
		//		packetID, timeDurationToMilliseconds(cd.CaptureEnd.Sub(cd.CaptureStart)), cd.TCPTsEnd-cd.TCPTsStart)
		//	printPacketInfo(eth, ipv4, tcp);
		//}

		res.ConnDataMap[conn]=cd;
	}		

	return res
}


// Calculates conversion factors from TCP timestamps to capture time milliseconds for each connection, storing them in the map provided  
func buildTimestampConversionTable(connDataMap map[Connection]ConnData) {
	ccdps:=make([]ConnectionConnDataPair, 0, len(connDataMap))
	for conn,cd := range(connDataMap) {
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

	numOutlierConnections:=0
	for _,ccdp:=range(ccdps) {
		captureDuration:=ccdp.CaptureEnd.Sub(ccdp.CaptureStart)
		captureMs      :=timeDurationToMilliseconds(captureDuration)
		if captureMs==0 {
			captureMs=1
		}

		tcpTsDelta     :=tcpTimestampDelta(ccdp.TCPTsStart, ccdp.TCPTsEnd)
		if tcpTsDelta==0 {
			tcpTsDelta=1
		}

		ccdp.MsPerTCPTs/=float32(ccdp.MsPerTCPTsCount)
		ccdp.MsPerTCPTsCount=1
		//ccdp.MsPerTCPTs   =float32(float64(captureMs)/float64(tcpTsDelta))
		if ccdp.MsPerTCPTs>0 && ccdp.MsPerTCPTs<1 {
			ccdp.MsPerTCPTs=1	
		}
		if ccdp.MsPerTCPTs<0 && ccdp.MsPerTCPTs>-1 {
			ccdp.MsPerTCPTs=-1	
		}

		connDataMap[ccdp.Connection]=ccdp.ConnData

		// print outliers only
		if ccdp.MsPerTCPTs<0.98 || ccdp.MsPerTCPTs>1.02 {
			log.Printf("%3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d syn %2d: %6d packets cap start %v end %v tcpts start %9d end %d delta %7d ms %7d tcpTs %1.2f ms/tcpTs\n", 
		           ccdp.SrcIP>>24, (ccdp.SrcIP>>16) & 0xff, (ccdp.SrcIP>>8) & 0xff, ccdp.SrcIP & 0xff, ccdp.SrcPort, 
		           ccdp.DstIP>>24, (ccdp.DstIP>>16) & 0xff, (ccdp.DstIP>>8) & 0xff, ccdp.DstIP & 0xff, ccdp.DstPort, 
		           ccdp.SynCount, ccdp.NumPackets,
		           ccdp.CaptureStart, ccdp.CaptureEnd, ccdp.TCPTsStart, ccdp.TCPTsEnd,
		           captureMs, tcpTsDelta, ccdp.MsPerTCPTs)
            numOutlierConnections++
        }
    }
    log.Printf("Total %d conversion ratio outliers (%f%% of connections)\n", numOutlierConnections, float64(numOutlierConnections)*100.0/float64(len(ccdps)))
}


// Find packets whose TCP timestamps differ from the wall clock by more than the expected time
func findOutliers(fileName string, connDataMap map[Connection]ConnData, thresholdMs int64) (res findOutliersInfo) {
	handleRead, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal("Error opening PCAP file:", err)
	}
	defer handleRead.Close()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var ipv6 layers.IPv6
	var tcp layers.TCP
	var payload gopacket.Payload

	parser  := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ipv4, &ipv6, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	synCountMap:=map[SrcDestPair]uint32{}
	var packetID uint64=0
	res.PacketIDs=map[uint64]int64{}

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

		var tcpTsSinceStart int64
		var tcpMsSinceStart int64
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
			tcpTs         :=tcpTimestampFromBytes(o.OptionData)
			tcpTsSinceStart=tcpTimestampDelta(cd.TCPTsStart, tcpTs)
			tcpMsSinceStart=int64(float64(tcpTsSinceStart)*float64(cd.MsPerTCPTs))

			// convert capture timestamp into estimated milliseconds since start of connection capture
			captureMsSinceStart=uint32(timeDurationToMilliseconds(ci.Timestamp.Sub(cd.CaptureStart)))
			deltaMs=int64(captureMsSinceStart)-int64(tcpMsSinceStart)
			if deltaMs>thresholdMs || deltaMs< (-thresholdMs) || cd.MsPerTCPTs<0 {
				res.PacketIDs[packetID]=deltaMs

				var b strings.Builder
				fmt.Fprintf(&b,"Packet %6d @ %v tcpts %9d connSince %6d ms %7d tcpts %7d tcpms delta %7d ms: ", 
					packetID, ci.Timestamp,  tcpTs, captureMsSinceStart, tcpTsSinceStart, tcpMsSinceStart, deltaMs)
				printPacketInfo(&b, eth, ipv4, tcp);
				log.Print(b.String())
			}
		}

		if !haveTCPTimestamp && cd.MsPerTCPTs<0 {
			res.PacketIDs[packetID]=999999999
			var b strings.Builder
			fmt.Fprintf(&b,"Packet %6d @ %v tcpts MISSING   connSince %6d ms MISSING tcpms delta MISSING ms: ", 
				packetID, ci.Timestamp,  timeDurationToMilliseconds(ci.Timestamp.Sub(cd.CaptureStart)))
			printPacketInfo(&b, eth, ipv4, tcp);
			log.Print(b.String())
		}

	}		

	return res
}

// Creates a uint32 TCP timestamp from byte array
func tcpTimestampFromBytes(ts []byte) uint32 {
	if len(ts)!=8 {
		return 0
	}
	return (uint32(ts[0])<<24) | (uint32(ts[1])<<16) | (uint32(ts[2])<<8) | (uint32(ts[3])<<0)  
}

// Calculates signed difference between TCP timestamps, keeping in mind the wraparound logic from https://tools.ietf.org/html/rfc7323#page-11
func tcpTimestampDelta(start, end uint32) int64 {
	delta     :=int64(end)
	if (end<start) && ((end-start)<(uint32(1)<<31)) {
		delta +=int64(1)<<32
	}
	delta     -=int64(start)
	return delta
}

// Converts given IP address to uint32
func ipToUInt32(ts []byte) uint32 {
	if len(ts)!=4 {
		return 0
	}
	return (uint32(ts[0])<<24) | (uint32(ts[1])<<16) | (uint32(ts[2])<<8) | (uint32(ts[3])<<0)  
}

// Pretty prints a packet
func printPacketInfo(b io.Writer, eth layers.Ethernet, ipv4 layers.IPv4, tcp layers.TCP) {
	fmt.Fprintf(b, "[%v] %v:%v -> ", eth.SrcMAC, ipv4.SrcIP, tcp.SrcPort)
	fmt.Fprintf(b, "%v:%v [%v]", ipv4.DstIP, tcp.DstPort, eth.DstMAC)
	fmt.Fprintf(b, " Seq %d Flags", tcp.Seq)
	if(tcp.FIN) { fmt.Fprintf(b, " FIN") }
	if(tcp.SYN) { fmt.Fprintf(b, " SYN") }
	if(tcp.RST) { fmt.Fprintf(b, " RST") }
	if(tcp.PSH) { fmt.Fprintf(b, " PSH") }
	if(tcp.ACK) { fmt.Fprintf(b, " ACK") }
	if(tcp.URG) { fmt.Fprintf(b, " URG") }
	if(tcp.ECE) { fmt.Fprintf(b, " ECE") }
	if(tcp.CWR) { fmt.Fprintf(b, " CWR") }
	if(tcp.NS)  { fmt.Fprintf(b, " NS")  }
}

func timeDurationToMilliseconds(d time.Duration) int64 {
	return d.Nanoseconds()/1000000
}