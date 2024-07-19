package portscan

import (
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/murrrda/goSweep/pkg/helpers"
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

func TcpScan(host string, startPort, endPort int) {
	localAddr, err := helpers.GetLocalAddr()
	if err != nil {
		fmt.Println(helpers.Red + err.Error() + helpers.Reset)
		return
	}
	nPorts := endPort - startPort + 1

	ports := make(chan int)
	res := make(chan scan)

	// spawn workers
	if nPorts > portWorkers {
		for i := 0; i < portWorkers; i++ {
			go worker(res, ports, host, localAddr)
		}
	} else {
		for i := 0; i < nPorts; i++ {
			go worker(res, ports, host, localAddr)
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
			fmt.Printf("%sPort %s OPEN\n%s", helpers.Green, r.Port.String(), helpers.Reset)
		case FILTERED:
			nFPorts++
		}
	}

	fmt.Printf("%d filtered ports (timeout)\n", nFPorts)
	fmt.Printf("Execution time: %.2f seconds\n", time.Since(timeStart).Seconds())
	close(res)
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
		return ERR, fmt.Errorf(helpers.Red + "Couln't parse dest ip" + helpers.Reset)
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
		return ERR, fmt.Errorf(helpers.Red + "Couldn't compute the checksum" + helpers.Reset + "\n" + err.Error())

	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		fmt.Println(helpers.Red + "Couldn't serialize layer" + helpers.Reset)
		fmt.Println(err)
		return ERR, fmt.Errorf(helpers.Red + "Couldn't serialize layer" + helpers.Reset + "\n" + err.Error())
	}

	conn, err := net.ListenPacket("ip4:tcp", "0")
	if err != nil {
		fmt.Println(helpers.Red + "Couldn't listen" + helpers.Reset)
		fmt.Println(err)
		return ERR, fmt.Errorf(helpers.Red + "Couldn't serialize layer" + helpers.Reset + "\n" + err.Error())
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
