package scanner

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type state uint8

const (
	reset    = "\033[0m"
	red      = "\033[31m"
	green    = "\033[32m"
	nWorkers = 500
)

const (
	OPEN state = iota
	CLOSED
	FILTERED
	ERR
)

type scan struct {
	Port  layers.TCPPort
	State state // OPEN(0), CLOSE(1), FILTERED(2)
}

func TcpScan(host string, startPort, endPort int) {
	localAddr, err := getLocalAddr()
	if err != nil {
		fmt.Println(red + err.Error() + reset)
		return
	}

	ports := make(chan int)
	res := make(chan scan)

	// spawn workers
	for i := 0; i < nWorkers; i++ {
		go worker(res, ports, host, localAddr)
	}

	timeStart := time.Now()
	go func() {
		for p := startPort; p <= endPort; p++ {
			ports <- p
		}

		close(ports)
	}()

	nPorts := endPort - startPort + 1
	nFPorts := 0
	for i := 1; i <= nPorts; i++ {
		r := <-res
		switch r.State {
		case OPEN:
			fmt.Printf("%sPort %s OPEN\n%s", green, r.Port.String(), reset)
		case FILTERED:
			nFPorts++
		}
	}

	fmt.Printf("%d filtered ports (timeout)\n", nFPorts)
	fmt.Printf("Execution time: %s\n", time.Since(timeStart))
}

func worker(res chan scan, ports chan int, host string, localAddr *net.UDPAddr) {
	for p := range ports {
		state, err := sendSynAndGetRes(localAddr, host, uint16(p))
		if err != nil {
			fmt.Println(err)
			continue
		}
		res <- scan{
			Port:  layers.TCPPort(p),
			State: state,
		}
	}
}

func sendSynAndGetRes(localAddr *net.UDPAddr, dstIp string, dstPort uint16) (state, error) {
	srcIp := localAddr.IP
	srcPort := layers.TCPPort(rand.Intn(65535-1024) + 1024) // Generate a random source port between 1024 and 65535

	dstIpNet := net.ParseIP(dstIp)
	if dstIpNet == nil {
		return ERR, fmt.Errorf(red + "Couln't parse dest ip" + reset)
	}

	ip := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIp,
		DstIP:    dstIpNet,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}

	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return ERR, fmt.Errorf(red + "Couldn't compute the checksum" + reset + "\n" + err.Error())

	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		fmt.Println(red + "Couldn't serialize layer" + reset)
		fmt.Println(err)
		return ERR, fmt.Errorf(red + "Couldn't serialize layer" + reset + "\n" + err.Error())
	}

	conn, err := net.ListenPacket("ip4:tcp", "0")
	if err != nil {
		fmt.Println(red + "Couldn't listen" + reset)
		fmt.Println(err)
		return ERR, fmt.Errorf(red + "Couldn't serialize layer" + reset + "\n" + err.Error())
	}
	defer conn.Close()

	// sending that SYN packet
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIpNet}); err != nil {
		return ERR, fmt.Errorf(err.Error())
	}

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return ERR, fmt.Errorf(err.Error())
	}

	// next step is to get servers response, which can be either SYN-ACK, RST or no response at all
	for {
		b := make([]byte, 4096)
		if n, _, err := conn.ReadFrom(b); err != nil {
			return FILTERED, nil
		} else {
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == layers.TCPPort(srcPort) && tcp.SYN && tcp.ACK {
					return OPEN, nil
				}
			}
		}
	}
}

func getLocalAddr() (*net.UDPAddr, error) {
	// 8.8.8.8 - Google DNS server
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr, nil
}

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
