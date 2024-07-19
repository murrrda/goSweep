package helpers

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	Gray   = "\033[37m"
	White  = "\033[97m"
)

// Find local IP address
func GetLocalAddr() (*net.UDPAddr, error) {
	// 8.8.8.8 - Google DNS server
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr, nil
}

// Parse port range provided in this format x:y
func ParsePortRange(portRange string) (int, int, error) {
	sePorts := strings.Split(portRange, ":")

	if len(sePorts) != 2 {
		return 0, 0, fmt.Errorf("You should provide port range <starting_port:end_port>")
	}

	startPort, err := strconv.Atoi(sePorts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("You should provide port range <starting_port:end_port>")
	}

	if startPort < 1 || startPort > 65535 {
		return 0, 0, fmt.Errorf("Ports should be in range 1:65535")
	}

	endPort, err := strconv.Atoi(sePorts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("You should provide port range <starting_port:end_port>")
	}

	if endPort < 1 || endPort > 65535 {
		return 0, 0, fmt.Errorf("Ports should be in range 1:65535")
	}

	return startPort, endPort, nil
}

// Calculate next IP address
func NextIP(ip *net.IP) {
	for j := len(*ip) - 1; j >= 0; j-- {
		(*ip)[j]++
		if (*ip)[j] > 0 {
			break
		}
	}
}

// Get all hosts from CIDR representation of a network
func GetHosts(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)

	if err != nil {
		return nil, err
	}
	fmt.Println("Network: " + ipNet.String())

	if ip.To4() == nil {
		return nil, fmt.Errorf("You should provide valid IPv4 address")
	}

	var ips []net.IP
	for currentIP := ip.Mask(ipNet.Mask); ipNet.Contains(currentIP); NextIP(&currentIP) {
		ipCopy := make(net.IP, len(currentIP))
		copy(ipCopy, currentIP)
		ips = append(ips, ipCopy)
	}

	// remove network and broadcast address
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}

	return ips, nil
}
