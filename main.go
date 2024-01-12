package main

import (
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ip to ping
const ip = "8.8.8.8"

func main() {
    log.Println("Hello, world!")

    pingIP(ip)
}


func pingIP(ip string) (string, error) {
    // resolving Ip addr
    ipAddr, err := net.ResolveIPAddr("ip", ip)
    if err != nil {
        log.Fatal("Error resolving IP: ", err)
    }

    // creating socket
    conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        log.Fatal("Error creating a socket: ", err)
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
        log.Fatal("Error Marshaling ICMP message: ", err)
    }

    startTime := time.Now()         // start counting time
    // send ICMP package
    _, err = conn.WriteTo(messageByted, ipAddr)
    if err != nil {
        log.Fatal("Error sending ICMP package: ", err)
    }

    replyBuffer := make([]byte, 1500)

    // receiving ICMP package
    _, _, err = conn.ReadFrom(replyBuffer)
    if err != nil {
        log.Fatal("Error receiving ICMP reply: ", err)
    }

    latency := time.Since(startTime)

    log.Println(latency)

    return "", err
}
