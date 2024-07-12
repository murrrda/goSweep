package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/murrrda/goSweep/internal/scanner"
)

func main() {
	subnetFlag := flag.String("s", "", "Subnet to ping sweep (e.g., 192.168.0.1/24)")
	portScanFlag := flag.String("ps", "", "Target host for port scanning (e.g., example.com, 192.168.0.1) and port range start:end")

	flag.Parse()

	if (*subnetFlag == "" && *portScanFlag == "") || (*subnetFlag != "" && *portScanFlag != "") {
		fmt.Println("Usage: ")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *subnetFlag != "" {
		scanner.PingSweep(*subnetFlag)
	} else if *portScanFlag != "" {
		args := flag.Args()
		if len(args) != 1 {
			flag.Usage()
			os.Exit(1)
		}
		startPort, endPort, err := scanner.ParsePortRange(args[0])
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
		scanner.TcpScan(ip, startPort, endPort)

	} else {
		flag.Usage()
	}

}
