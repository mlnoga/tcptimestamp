# tcptimestamp
A tool which hunts for TCP timestamp inconsistencies in PCAP files 

# Background
* [RFC7323](https://tools.ietf.org/html/rfc7323) TCP Extensions for high performance
* [GoPacket](https://github.com/google/gopacket) library
* [Examples](https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket) for GoPacket
* [PCAP](https://pcapng.github.io/pcapng/draft-gharris-opsawg-pcap.html) file format

# Prerequisites
* go v1.10 or higher
* gcc
* libpcap
* libpcap-devel

# Build
`go build` 

# Run 
* `mkdir -p traces/`
* Put or symlink the desired traces in there
* `./run.sh`
