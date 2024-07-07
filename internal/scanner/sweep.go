package scanner

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

func PingSweep(subnetFlag string) {
	hosts, err := getHosts(subnetFlag)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var wg sync.WaitGroup

	timeStart := time.Now()
	for _, host := range hosts {
		wg.Add(1)
		go pingIP(&wg, host)
	}
	wg.Wait()

	elapsed := time.Since(timeStart)
	fmt.Printf("Execution time: %v\n", elapsed.String())
}

func nextIP(ip *net.IP) {
	for j := len(*ip) - 1; j >= 0; j-- {
		(*ip)[j]++
		if (*ip)[j] > 0 {
			break
		}
	}
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

func getHosts(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)

	if err != nil {
		return nil, err
	}

	if ip.To4() == nil {
		return nil, fmt.Errorf("You should provide valid IPv4 address")
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); nextIP(&ip) {
		ips = append(ips, ip.String())
	}

	// remove netword and broadcast address
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}
