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

	"github.com/valyala/fastrand"
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
	NumPackets      uint32
	NumBytes        int
	CaptureStart	time.Time
	CaptureEnd      time.Time
}

type TimingPair struct {
	Capture 	 time.Time
	TCPTimestamp uint32
}

type ConnData struct {
	CaptureData

	TCPTsStart      uint32
	TCPTsEnd        uint32

	TimingPairs   []TimingPair   // for calculation of conversion factor. nil'ed afterwards to free memory
	MsPerTCPTs      float32      // conversion factor
	MsOffset        float32      // offset factor
}

type ConnectionConnDataPair struct {
	Connection
	ConnData
}

// Global trace analysis results
type GlobalStats struct {
	CaptureData

	PacketsEthernet   int
	PacketsDot1Q      int
	PacketsIPv4       int
	PacketsTCP        int

	SynCountMap       map[SrcDestPair]uint32
	ConnDataMap 	  map[Connection]ConnData
}


var rng = fastrand.RNG{}


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
	stats:=collectStartEndTimes(*readFileName)

	duration:=stats.CaptureEnd.Sub(stats.CaptureStart)
	log.Printf("Capture covers time from  %v to %v (%v)\n",stats.CaptureStart, stats.CaptureEnd, duration)
    log.Printf("Total %d packets of size %d at %.1f packets/second\n", 
		stats.NumPackets, stats.NumBytes, float64(stats.NumPackets)/duration.Seconds())
    log.Printf("Thereof %d ethernet, %d Dot1Q, %d ipv4 and %d tcp\n", 
		stats.PacketsEthernet, stats.PacketsDot1Q, stats.PacketsIPv4, stats.PacketsTCP)
	log.Printf("Found %d connections based on src/dst ip, src/dest port and syn count.\n", len(stats.ConnDataMap))

	// Build conversion table
	log.Printf("\nBuild TCP timestamp/ms conversions\n----------------------------------\n")
	buildTimestampConversionTable(stats.ConnDataMap)

	// Find outliers
	log.Printf("\nFind Outliers\n-------------\n")
	findOutliers(*readFileName, stats.ConnDataMap, *threshold)

	log.Printf("\nExiting after %v\n", time.Since(start).Truncate(100*time.Millisecond))	
}


// Find connections and collect wall clock and TCP timestamps per connection
func collectStartEndTimes(fileName string) (res GlobalStats) {
	handleRead, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal("Error opening PCAP file:", err)
	}
	defer handleRead.Close()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	parser  := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ipv4, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	var packetID uint64=0
	res.SynCountMap=map[SrcDestPair]uint32{}
	res.ConnDataMap=map[Connection]ConnData{}

	parserErrors:=map[string]uint32{}
	// var b strings.Builder

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
			if parserErrors[err.Error()]==0 {
				log.Printf("Warning: packet %6d: %s; skipping in this and all future packets\n", packetID, err)
			}
			parserErrors[err.Error()]++
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
			tcpTimestamp:=tcpTimestampFromBytes(o.OptionData)
			if cd.NumPackets<=1 {
				cd.TCPTsStart=tcpTimestamp
			}
			cd.TCPTsEnd=tcpTimestamp

			tp:=TimingPair{ Capture:ci.Timestamp, TCPTimestamp:tcpTimestamp }
			cd.TimingPairs=append(cd.TimingPairs, tp)

			// For debugging
			// if tcp.SrcPort==726 && tcp.DstPort==2049 {
			// 	b.Reset()
			// 	captureMs:=timeDurationToMilliseconds(ci.Timestamp.Sub(cd.CaptureStart))
			// 	tcpTimestampDelta:=tcpTimestampDelta(cd.TCPTsStart, cd.TCPTsEnd)
			// 	fmt.Fprintf(&b, "XX Packet %6d @ %6d ms %6d tcpts %5d delta: ", 
			// 		        packetID, captureMs, tcpTimestampDelta, captureMs-tcpTimestampDelta)
			// 	printPacketInfo(&b, eth, ipv4, tcp);
			// 	log.Print(b.String())
			// }

			break;
		}

		res.ConnDataMap[conn]=cd;
	}		

	if len(parserErrors)>0 {
		log.Print("\nError summary:")
		numErrors:=uint32(0)
		for k,v :=range parserErrors {
			log.Printf("%6d times %v", v, k)
			numErrors+=v
		}		
		log.Printf("%6d parser errors total", numErrors)
		log.Print("")
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
	for c,ccdp:=range(ccdps) {
		captureDuration:=ccdp.CaptureEnd.Sub(ccdp.CaptureStart)
		captureMs      :=timeDurationToMilliseconds(captureDuration)
		if captureMs==0 {
			captureMs=1
		}

		tcpTsDelta     :=tcpTimestampDelta(ccdp.TCPTsStart, ccdp.TCPTsEnd)
		if tcpTsDelta==0 {
			tcpTsDelta=1
		}

		// ccdp.MsPerTCPTs/=float32(ccdp.MsPerTCPTsCount)
		// ccdp.MsPerTCPTsCount=1

		//ccdp.MsPerTCPTs   =float32(float64(captureMs)/float64(tcpTsDelta))

		ccdp.MsPerTCPTs=estimateSlope(ccdp.TimingPairs)
		// if ccdp.MsPerTCPTs>0 && ccdp.MsPerTCPTs<1 {
		// 	ccdp.MsPerTCPTs=1	
		// }
		if ccdp.MsPerTCPTs<0 && ccdp.MsPerTCPTs>-1 {
			ccdp.MsPerTCPTs=-1	
		}
		ccdp.MsOffset  =estimateIntercept(ccdp.TimingPairs, ccdp.MsPerTCPTs)
		ccdp.TimingPairs=nil // free memory

		connDataMap[ccdp.Connection]=ccdp.ConnData


		// print outliers only
		if captureMs>500 && !(
			(ccdp.MsPerTCPTs>=0.97 && ccdp.MsPerTCPTs<=1.03) ||
			(ccdp.MsPerTCPTs>=3.97 && ccdp.MsPerTCPTs<=4.03)    ) && !(ccdp.MsOffset>=-1 && ccdp.MsOffset<=1)  {
            numOutlierConnections++
			log.Printf("Conn %4d: %3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d syn %2d: %6d packets cap start %v end %v tcpts start %9d end %d delta %7d ms %7d tcpTs ms=%1.2fx tcpts %+1.2f\n", 
		           c,
		           ccdp.SrcIP>>24, (ccdp.SrcIP>>16) & 0xff, (ccdp.SrcIP>>8) & 0xff, ccdp.SrcIP & 0xff, ccdp.SrcPort, 
		           ccdp.DstIP>>24, (ccdp.DstIP>>16) & 0xff, (ccdp.DstIP>>8) & 0xff, ccdp.DstIP & 0xff, ccdp.DstPort, 
		           ccdp.SynCount, ccdp.NumPackets,
		           ccdp.CaptureStart, ccdp.CaptureEnd, ccdp.TCPTsStart, ccdp.TCPTsEnd,
		           captureMs, tcpTsDelta, ccdp.MsPerTCPTs, ccdp.MsOffset)
        }
    }
    log.Printf("Total %d conversion ratio outliers (%f%% of connections)\n", numOutlierConnections, float64(numOutlierConnections)*100.0/float64(len(ccdps)))
}

// Estimate the slope of the conversion from TCP timestamps to wall clock milliseconds.
// Uses the median of the slope between randomly sampled pairs.
func estimateSlope(tp []TimingPair) float32 {
	l:=uint32(len(tp))
	if l<2 {
		return 1
	} else if l==2 {
		captureMsDelta   :=timeDurationToMilliseconds(tp[1].Capture.Sub(tp[0].Capture))
		if captureMsDelta==0 { return 1.0 }
		tcpTimestampDelta:=tcpTimestampDelta(tp[0].TCPTimestamp, tp[1].TCPTimestamp)
		if tcpTimestampDelta==0 { return 1.0 }
		return float32(captureMsDelta) / float32(tcpTimestampDelta)
	}

	samplesToTake:=20*l
	samples:=make([]float32, samplesToTake)
	samplesTaken:=0

	// calculate ratios
	for num:=uint32(0); num<samplesToTake; num++ {
		i:=    rng.Uint32n(l/3) 
		j:=l-1-rng.Uint32n(l/3)

		captureMsDelta   :=timeDurationToMilliseconds(tp[j].Capture.Sub(tp[i].Capture))
		if captureMsDelta==0 { continue }
		tcpTimestampDelta:=tcpTimestampDelta(tp[i].TCPTimestamp, tp[j].TCPTimestamp)
		if tcpTimestampDelta==0 { continue }

		sample := float32(captureMsDelta) / float32(tcpTimestampDelta)
		samples[samplesTaken]=sample
		samplesTaken++
	}
	if samplesTaken==0 {
		return 1.0
	}

	// use median as statistically robust estimator in the presence of outliers
	return QSelectMedianFloat32(samples[:samplesTaken])
}


// Estimate the intercept, given the slope
func estimateIntercept(tp []TimingPair, msPerTCPTs float32) float32 {
	l:=uint32(len(tp))
	if l<2 {
		return 1
	} else if l==2 {
		captureMsDelta   :=timeDurationToMilliseconds(tp[1].Capture.Sub(tp[0].Capture))
		if captureMsDelta==0 { return 0.0 }
		tcpTimestampDelta:=tcpTimestampDelta(tp[0].TCPTimestamp, tp[1].TCPTimestamp)
		if tcpTimestampDelta==0 { return 0.0 }
		return float32(captureMsDelta) / float32(tcpTimestampDelta)
	}

	samplesToTake:=20*l
	samples:=make([]float32, samplesToTake)
	samplesTaken:=0

	// calculate ratios
	for num:=uint32(0); num<samplesToTake; num++ {
		i:=    rng.Uint32n(l/3) 
		j:=l-1-rng.Uint32n(l/3)

		captureMsDelta   :=timeDurationToMilliseconds(tp[j].Capture.Sub(tp[i].Capture))
		if captureMsDelta==0 { continue }
		tcpTimestampDelta:=tcpTimestampDelta(tp[i].TCPTimestamp, tp[j].TCPTimestamp)
		if tcpTimestampDelta==0 { continue }

		sample := float32(captureMsDelta) - float32(tcpTimestampDelta)*msPerTCPTs
		samples[samplesTaken]=sample
		samplesTaken++
	}
	if samplesTaken==0 {
		return 0.0
	}

	// use median as statistically robust estimator in the presence of outliers
	return QSelectMedianFloat32(samples[:samplesTaken])
}


// Select median of an array of float32. Partially reorders the array.
// Array must not contain IEEE NaN
func QSelectMedianFloat32(a []float32) float32 {
    return QSelectFloat32(a, (len(a)>>1)+1)
}


// Select kth lowest element from an array of float32. Partially reorders the array.
// Array must not contain IEEE NaN
func QSelectFloat32(a []float32, k int) float32 {
    left, right:=0, len(a)-1
    for left<right {
        // partition
        mid:=(left+right)>>1
        pivot := a[mid]
        l, r  := left-1, right+1
        for {
            for {
                l++
                // if l>=len(a) { CheckNaNs(a) }
                if a[l]>=pivot { break }
            }
            for {
                r--
                // if r<0 { CheckNaNs(a) }
                if a[r]<=pivot { break }
            }
            if l >= r { break } // index in r
            a[l], a[r] = a[r], a[l]
        }
        index:=r

        offset:=index-left+1
        if k<=offset {
            right=index
        } else {
            left=index+1
            k=k-offset
        }
    }
    return a[left]
}


// Find packets whose TCP timestamps differ from the wall clock by more than the expected time
func findOutliers(fileName string, connDataMap map[Connection]ConnData, thresholdMs int64) {
	handleRead, err := pcap.OpenOffline(fileName)
	if err != nil {
		log.Fatal("Error opening PCAP file:", err)
	}
	defer handleRead.Close()

	var eth layers.Ethernet
	var dot1q layers.Dot1Q
	var ipv4 layers.IPv4
	var tcp layers.TCP
	var payload gopacket.Payload

	parser  := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &dot1q, &ipv4, &tcp, &payload)
	decoded := []gopacket.LayerType{}

	synCountMap:=map[SrcDestPair]uint32{}
	var packetID uint64=0
	var numPacketsTCP uint64

	var numOutliers uint32=0

	var b strings.Builder

	for {
		data, ci, err := handleRead.ReadPacketData()
		if err != nil && err != io.EOF {
			log.Fatal(err)
		} else if err == io.EOF {
			break
		} 
		
		packetID++
		if err := parser.DecodeLayers(data, &decoded); err != nil {
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
			case layers.LayerTypeTCP:
			  	haveTCP=true
			  	numPacketsTCP++
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
			tcpMsSinceStart=int64(float64(tcpTsSinceStart)*float64(cd.MsPerTCPTs)+float64(cd.MsOffset))

			// convert capture timestamp into estimated milliseconds since start of connection capture
			captureMsSinceStart=uint32(timeDurationToMilliseconds(ci.Timestamp.Sub(cd.CaptureStart)))
			deltaMs=int64(captureMsSinceStart)-int64(tcpMsSinceStart)
			if deltaMs>thresholdMs || deltaMs< (-thresholdMs) || cd.MsPerTCPTs<0 {
				b.Reset()
				fmt.Fprintf(&b,"Pack %6d: %3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d syn %2d: captured %v tcpts %9d capms %7d tcpms %7d delta %6d ", 
	            packetID,
	            conn.SrcIP>>24, (conn.SrcIP>>16) & 0xff, (conn.SrcIP>>8) & 0xff, conn.SrcIP & 0xff, conn.SrcPort, 
	            conn.DstIP>>24, (conn.DstIP>>16) & 0xff, (conn.DstIP>>8) & 0xff, conn.DstIP & 0xff, conn.DstPort, 
	            conn.SynCount, ci.Timestamp, tcpTs, captureMsSinceStart, tcpMsSinceStart, deltaMs)
				printPacketInfo(&b, eth, ipv4, tcp);
				log.Print(b.String())
				numOutliers++
			}
		}

		if !haveTCPTimestamp {
			b.Reset()
			fmt.Fprintf(&b,"Pack %6d: %3d.%3d.%3d.%3d:%5d -> %3d.%3d.%3d.%3d:%5d syn %2d: captured %v tcpts NONE      capms %7d tcpms NONE    delta NONE   ", 
	            packetID,
	            conn.SrcIP>>24, (conn.SrcIP>>16) & 0xff, (conn.SrcIP>>8) & 0xff, conn.SrcIP & 0xff, conn.SrcPort, 
	            conn.DstIP>>24, (conn.DstIP>>16) & 0xff, (conn.DstIP>>8) & 0xff, conn.DstIP & 0xff, conn.DstPort, 
	            conn.SynCount, ci.Timestamp, captureMsSinceStart)
			printPacketInfo(&b, eth, ipv4, tcp);
			log.Print(b.String())
			numOutliers++
		}
	}		

	log.Printf("Total %d outlier packets (%f%% of TCP packets).\n", numOutliers, float64(numOutliers)*100.0/float64(numPacketsTCP))
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
	//fmt.Fprintf(b, "[%v] %v:%v -> ", eth.SrcMAC, ipv4.SrcIP, tcp.SrcPort)
	//fmt.Fprintf(b, "%v:%v [%v]", ipv4.DstIP, tcp.DstPort, eth.DstMAC)
	fmt.Fprintf(b, " seq %d flags", tcp.Seq)
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