package main

import (
    "log"
    "net"
    "os"
    "strings"
    "time"
    "strconv"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

func main() {
    if len(os.Args) != 2 {
        log.Fatal("You should provide IP address")
    }
    targetAddr := os.Args[1]

    if strings.Count(targetAddr, "x") > 0 {
        targetAddr = strings.Replace(targetAddr, "x", strconv.FormatInt(int64(0), 10), -1)
        pingIP(targetAddr)
    }
        pingIP(targetAddr)
    //for _, v := range []int{0, 256} {

    //}
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
    _, _, err = conn.ReadFrom(replyBuffer)
    if err != nil {
        log.Println("No reply (%v): %v", ip, err)
        return "", err
    }

    latency := time.Since(startTime)

    log.Println(ip)
    log.Println(latency)

    return ip + " time: " +latency.String(), nil
}
