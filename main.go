package main

import (
    "log"
    "net"
    "os"
    //"sync"
    "time"
    "strconv"
    "strings"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)


func main() {
    //if len(os.Args) != 2 {
    //    log.Fatal("You should provide IP address in CIDR notation")
    //}
    //targetAddr := os.Args[1]
    ip := "192.168.0.20"

    //ip, ipNet, err := net.ParseCIDR(targetAddr)
    //if err != nil {
    //    log.Fatal("Error parsing -- please provide input in CIDR notation: 192.168.0.1/24 for example")
    //}

    for i := 20; i < 256; i++ {
        ipParts := strings.Split(ip, ".")

        ipParts[3] = strconv.Itoa(i)

        newIp := strings.Join(ipParts, ".")
        pingIP(newIp)
    }

    //var wg sync.WaitGroup
    //// Ping all IP addresses in the network
    //for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
    //    ipStr := ip.String()
    //    wg.Add(1)
    //    go func(ipStr string) {
    //        defer wg.Done()

    //        _, err := pingIP(ipStr)
    //        if err != nil {
    //            log.Println(err)
    //        } else {
    //            //log.Println(result)
    //        }
    //    }(ipStr)
    //}
    //// Wait for all goroutines to finish
    //wg.Wait()
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func pingIP(ip string) (string, error) {
    // resolving Ip addr
    ipAddr, err := net.ResolveIPAddr("ip", ip)
    if err != nil {
        log.Println("Error resolving IP: ", err)
        return "", err
    }

    // creating socket
    conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        log.Println("Error creating socket: ", err)
        return "", err
    }
    defer conn.Close()

    // creating ICMP message
    message := icmp.Message {
        Type:     ipv4.ICMPTypeEcho,
        Code:     0,
        Body:     &icmp.Echo {
            ID:   os.Getpid() & 0xffff,
            Seq:  1,
            Data: []byte("Hello-Friend!"),
        },
    }

    // converting message to bytes (Marshaling)
    messageByted, err := message.Marshal(nil)
    if err != nil {
        log.Println("Error Marshaling ICMP message: ", err)
        return "", err
    }

     // start counting time
    startTime := time.Now()
    // send ICMP package
    _, err = conn.WriteTo(messageByted, ipAddr)
    if err != nil {
        log.Println("Error sending ICMP message: ", err)
        return "", err
    }

    replyBuffer := make([]byte, 1500)

    // receiving ICMP reply
    icmpInt, icmpNetAddr, err := conn.ReadFrom(replyBuffer)
    if err != nil {
        log.Printf("No reply (%v): %v\n", ip, err)
        return "", err
    }

    // Parse the received ICMP packet
    receivedMsg, err := icmp.ParseMessage(1, replyBuffer[:icmpInt])
    if err != nil {
        log.Println("Error parsing ICMP reply: ", err)
        return "", err
    }

    // Check if the received packet is an echo reply
    switch receivedMsg.Type {
    case ipv4.ICMPTypeEchoReply:
        log.Printf("Received reply from %v: %v\n", ip, icmpNetAddr)
        // Further processing or return as needed
    default:
        log.Printf("Received unexpected ICMP type %v from %v\n", receivedMsg.Type, ip)
    }

    latency := time.Since(startTime)

    return ip + " time: " +latency.String(), nil
}
