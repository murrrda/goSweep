package main

import (
    "fmt"
    "net"
    "os"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
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
        fmt.Println("Error parsing -- you should provide input in CIDR notation")
        os.Exit(1)
    }

    // calculating first and last IP in range
    start := ipNet.IP.Mask(ipNet.Mask)
    end := net.IP(make([]byte, len(start)))
    copy(end, start)
    for i := 0; i < len(start); i++ {
        end[i] |= ^ipNet.Mask[i]
    }

    // Iterate over the usable IP addresses in the range
    for ip := nextIP(start); !ip.Equal(end); ip = nextIP(ip) {
        pingIP(ip.String())
    }
}

func ParseCIDR(cidr string) (*net.IPNet, error) {
    ip, ipNet, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, err
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

func pingIP(ip string) (string, error) {
    // resolving Ip addr
    ipAddr, err := net.ResolveIPAddr("ip", ip)
    if err != nil {
        fmt.Println("Error resolving IP: ", err)
        return "", err
    }

    // creating socket
    conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        fmt.Println("Error creating socket: ", err)
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
        fmt.Println("Error Marshaling ICMP message: ", err)
        return "", err
    }

     // start counting time
    startTime := time.Now()
    // send ICMP package
    _, err = conn.WriteTo(messageByted, ipAddr)
    if err != nil {
        fmt.Println("Error sending ICMP message: ", err)
        return "", err
    }

    replyBuffer := make([]byte, 1500)

    // receiving ICMP reply
    icmpInt, _, _ := conn.ReadFrom(replyBuffer)

    // Parse the received ICMP packet
    receivedMsg, err := icmp.ParseMessage(1, replyBuffer[:icmpInt])
    if err != nil {
        fmt.Println("Error parsing ICMP reply: ", err)
        return "", err
    }

    // Check if the received packet is an echo reply
    fmt.Printf("Received ICMP type: %v from %v\n", receivedMsg.Type, ip)

    latency := time.Since(startTime)

    return ip + " time: " +latency.String(), nil
}
