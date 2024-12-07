package portscan

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/murrrda/goSweep/pkg/output"
	"github.com/murrrda/goSweep/pkg/utils"
)

type state uint8

const portWorkers = 300

const (
	OPEN state = iota
	CLOSED
	FILTERED
	ERR
)

type scan struct {
	Port  layers.TCPPort
	State state // OPEN(0), CLOSE(1), FILTERED
}

func printStart(host, ip string, startPort, endPort int, formatter output.Formatter) {
	formatter.Header(time.Now().Format("January 02, 2006 15:04:05 MST"))
	formatter.Info("Beggining Port Scan...\n")
	formatter.Info(fmt.Sprintf("Host %v (%v)", host, ip))
	formatter.Info(fmt.Sprintf("Port range %v:%v", startPort, endPort))
	formatter.Footer()
}

func TcpScan(host string, startPort, endPort int, formatter output.Formatter) {
	ips, err := net.LookupIP(host)
	if err != nil {
		fmt.Println("%w\n", err)
		return
	}
	ip := ips[0].To4().String()
	printStart(host, ip, startPort, endPort, formatter)
	localAddr, err := utils.GetLocalIp()
	if err != nil {
		formatter.Error(err.Error())
		return
	}
	nPorts := endPort - startPort + 1

	ports := make(chan int)
	res := make(chan scan)

	// spawn workers
	if nPorts > portWorkers {
		for i := 0; i < portWorkers; i++ {
			go worker(res, ports, ip, localAddr, formatter)
		}
	} else {
		for i := 0; i < nPorts; i++ {
			go worker(res, ports, ip, localAddr, formatter)
		}
	}

	timeStart := time.Now()
	go func() {
		for p := startPort; p <= endPort; p++ {
			ports <- p
		}

		close(ports)
	}()

	nFPorts := 0 // number of filtered ports
	for i := 0; i < nPorts; i++ {
		r := <-res
		switch r.State {
		case OPEN:
			formatter.Success(fmt.Sprintf("Port %s OPEN", r.Port.String()))

		case FILTERED:
			nFPorts++
		}
	}

	formatter.Info(fmt.Sprintf("%d filtered ports (timeout)", nFPorts))
	formatter.Info(fmt.Sprintf("Execution time: %.2f seconds", time.Since(timeStart).Seconds()))
	formatter.Footer()
	close(res)
}

func worker(res chan scan, ports chan int, host string, localAddr *net.UDPAddr, formatter output.Formatter) {
	for p := range ports {
		state, err := sendSynAndGetRes(localAddr, host, uint16(p))
		if err != nil {
			formatter.Error(err.Error())
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
		return ERR, fmt.Errorf("Couln't parse destination ip")
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
		return ERR, fmt.Errorf("Couldn't compute the checksum:\n%w", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		return ERR, fmt.Errorf("Couldn't serialize layer:\n%w", err)
	}

	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return ERR, fmt.Errorf("Couldn't listen:\n%w", err)
	}
	defer conn.Close()

	// sending that SYN packet
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstIpNet}); err != nil {
		return ERR, fmt.Errorf("%w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return ERR, fmt.Errorf("%w", err)
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
				if tcp.DstPort == layers.TCPPort(srcPort) {
					if tcp.SYN && tcp.ACK {
						return OPEN, nil
					} else if tcp.RST {
						return CLOSED, nil
					}
				}
			}
		}
	}
}
