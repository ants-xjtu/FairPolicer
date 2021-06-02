# FairPolicer
This is a software prototype of FairPolicer,
which is implemented as a kernel module.
FairPolicer is a network traffic policer
that can fairly allocate bandwidth among contending flows
regardless of their congestion control algorithms.

Details of FairPolicer can be found at our paper
"Towards the Fairness of Traffic Policer", which was presented at INFOCOM'21.

## Requirements
- Linux 5.4.0
- Kernel headers

## How to use
### Disabling offload on network devices (e.g., `eth0`)
``` bash
ethtool -K eth0 tso off gso off gro off lro off
```
This command disables offload features of `eth0`
to better emulate a switch.

### Compile kernel module
``` bash
make
```

### Insert kernel module
``` bash
insert-module.sh 4 1024
```
This command configures the FairPolicer with a 4*1024 Count-Min Sketch
and inserts it into the kernel.

### Installing `qdisc` on a network device (e.g., `eth0`)
``` bash
tc qdisc add dev eth0 root tbf rate 10mbit burst 180kb limit 1600b
```
This command enables FairPolicer at `eth0`, allowing 180KB traffic burst
and throttling overall traffic rate to 10Mbps.

## Contact
If you have any questions, contact [Danfeng Shan](https://dfshan.github.io/).
