package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const nWorkers = 100

func TcpScan(host string, startPort, endPort int) {
	ports := make(chan int, nWorkers)
	res := make(chan int)

	// spawn workers
	for i := 0; i < nWorkers; i++ {
		go worker(ports, res, host)
	}

	go func() {
		for p := startPort; p <= endPort; p++ {
			ports <- p
		}
	}()

	for cap(res) != 0 {
		port := <-res
		if port != 0 {
			fmt.Printf("Port %d open\n", port)
		}
	}

	close(ports)
	close(res)
}

// parses start:end port
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

func worker(ports chan int, res chan int, host string) {
	for p := range ports {
		conn, err := net.Dial("tcp", host+":"+strconv.Itoa(p))
		if err != nil {
			res <- 0
			continue
		}
		conn.Close()
		res <- p
	}
}
