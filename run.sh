#/bin/bash
./main -r 'traces/a0b_pktt_trace_12_Mar_13_1226.trc'        -i 10.104.240.97  | tee 'a0b_pktt_trace_12_Mar_13_1226.analysis'
./main -r 'traces/2021-03-22T01:39:25-vsa8123371_eth1.pcap' -i 10.104.240.54  | tee '2021-03-22T01:39:25-vsa8123371_eth1.analysis'
./main -r 'traces/2021-03-22T05:39:51-vsa8034183_eth1.pcap' -i 10.104.240.118 | tee '2021-03-22T05:39:51-vsa8034183_eth1.analysis'
