package main

import (
	"flag"
	"fmt"
	"github.com/murrrda/goSweep/internal/scanner"
	"os"
)

func main() {
	subnetFlag := flag.String("s", "", "Subnet to ping sweep (e.g., 192.168.0.1/24)")
	portScanFlag := flag.String("ps", "", "Target host for port scanning (e.g., example.com)")

	flag.Parse()

	if (*subnetFlag == "" && *portScanFlag == "") || (*subnetFlag != "" && *portScanFlag != "") {
		fmt.Println("Usage: ")
		flag.PrintDefaults()
		fmt.Println("For port scan: -ps <target> <port-range>")
		os.Exit(1)
	}

	if *subnetFlag != "" {
		scanner.PingSweep(*subnetFlag)
	} else {
		args := flag.Args()
		if len(args) != 1 {
			os.Exit(1)
		}
		startPort, endPort, err := scanner.ParsePortRange(args[0])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		scanner.TcpScan(*portScanFlag, startPort, endPort)
	}

}
