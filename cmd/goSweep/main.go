package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/murrrda/goSweep/pkg/helpers"
	"github.com/murrrda/goSweep/pkg/portscan"
	"github.com/murrrda/goSweep/pkg/sweep"
)

func main() {
	subnetFlag := flag.String("s", "", "Network to ping sweep (e.g., 192.168.0.1/24)")
	portScanFlag := flag.String("ps", "", "Target host for port scanning (e.g., example.com, 192.168.0.1) and port range start:end (e.g. 1:1024)")

	flag.Parse()

	if (*subnetFlag == "" && *portScanFlag == "") || (*subnetFlag != "" && *portScanFlag != "") {
		fmt.Println("Usage: ")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *subnetFlag != "" {
		sweep.PingSweep(*subnetFlag)
	} else if *portScanFlag != "" {
		args := flag.Args()
		if len(args) != 1 {
			flag.Usage()
			os.Exit(1)
		}
		startPort, endPort, err := helpers.ParsePortRange(args[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		ips, err := net.LookupIP(*portScanFlag)
		if err != nil {
			fmt.Println("Coulnd't lookup your ipv4")
			os.Exit(1)
		}
		ip := ips[0].To4().String()

		fmt.Println("Performing SYN port scan for ", *portScanFlag, "(", ip, ")")
		portscan.TcpScan(ip, startPort, endPort)

	} else {
		flag.Usage()
	}

}
