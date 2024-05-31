package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("You should provide IP address in CIDR notation")
		os.Exit(1)
	}
	cidrInput := os.Args[1]

	// parsing input
	ipNet, err := ParseCIDR(cidrInput)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	// calculating first and last IP in range
	start := ipNet.IP.Mask(ipNet.Mask)
	end := net.IP(make([]byte, len(start)))
	copy(end, start)
	for i := 0; i < len(start); i++ {
		end[i] |= ^ipNet.Mask[i]
	}

	timeStart := time.Now()
	var wg sync.WaitGroup

	// Iterate over the usable IP addresses in the range
	for ip := nextIP(start); !ip.Equal(end); ip = nextIP(ip) {
		wg.Add(1)
		go pingIP(&wg, ip.String())
	}
	wg.Wait()

	elapsed := time.Since(timeStart)
	fmt.Printf("Execution time: %v\n", elapsed.String())
}

func ParseCIDR(cidr string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(ipNet.String(), "32") {
		return nil, fmt.Errorf("Provide a valid mask")
	}

	ipNet.IP = ip
	return ipNet, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)

	for j := len(next) - 1; j >= 0; j-- {
		next[j]++
		if next[j] > 0 {
			break
		}
	}
	return next
}

func pingIP(wg *sync.WaitGroup, ip string) {
	defer wg.Done()

	cmd := exec.Command("ping", "-c", "1", ip)

	_, err := cmd.CombinedOutput()
	if err != nil {
		//fmt.Printf("Error pinging %v\n", ip)
	} else {
		fmt.Printf("Echo reply from %v\n", ip)
	}
}
