# tcptimestamp
A tool which hunts for TCP timestamp inconsistencies in .pcap files 

# Prerequisites
* go v1.9 or higher
* gcc
* libpcap
* libpcap-devel

# Build
`go build` 

# Run 
* `mkdir -p traces/`
* Put or symlink the desired traces in there
* `./run.sh`
