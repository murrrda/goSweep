package utils

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Wrapper around dnsmessage.Message.
// Purpose is to attach sendQuery method to it
// and encapsulate writing and reading to and from the socket
type dnsMsg struct {
	msg dnsmessage.Message
}

// Method to send dns query, receive and parse response.
func (d *dnsMsg) sendQuery(dnsServer string) (dnsmessage.Message, error) {
	// packing already configured dnsmessage
	packet, err := d.msg.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}

	conn, err := net.Dial("udp", dnsServer+":53")
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		fmt.Println("set deadline fail")
		return dnsmessage.Message{}, err
	}

	// Send the DNS query packet
	_, err = conn.Write(packet)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	var response dnsmessage.Message
	// Unmarshal the DNS response
	err = response.Unpack(buffer[:n])
	if err != nil {
		return dnsmessage.Message{}, err
	}

	return response, nil
}

func DnsQueryMX(domain string, dnsServer string) ([]string, error) {
	var dnsMessage dnsmessage.Message
	dnsMessage.Header.RecursionDesired = true
	dnsMessage.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(domain),
			Type:  dnsmessage.TypeMX,
			Class: dnsmessage.ClassINET,
		},
	}

	dnsQuery := dnsMsg{
		msg: dnsMessage,
	}

	response, err := dnsQuery.sendQuery(dnsServer)
	if err != nil {
		return nil, err
	}

	// Collect IP addresses from the answer section
	var ips []string
	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeMX {
			ip := answer.Body.(*dnsmessage.MXResource).MX.String()
			ips = append(ips, ip)
		}
	}

	return ips, nil
}

func DnsQueryAAAA(domain string, dnsServer string) ([]string, error) {
	// Create a DNS message for an A record lookup (IPv4)
	var dnsMessage dnsmessage.Message
	dnsMessage.Header.RecursionDesired = true
	dnsMessage.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(domain),
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
		},
	}

	dnsQuery := dnsMsg{
		msg: dnsMessage,
	}

	response, err := dnsQuery.sendQuery(dnsServer)
	if err != nil {
		return nil, err
	}

	// Collect IP addresses from the answer section
	var ips []string
	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeAAAA {
			ip := answer.Body.(*dnsmessage.AAAAResource).AAAA
			ips = append(ips, net.IP(ip[:]).String())
		}
	}

	return ips, nil
}

func DnsQueryCNAME(domain string, dnsServer string) (string, error) {
	if len(domain) == 0 {
		return "", nil
	}
	// Create a DNS message for an A record lookup (IPv4)
	var dnsMessage dnsmessage.Message
	dnsMessage.Header.RecursionDesired = true
	dnsMessage.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(domain),
			Type:  dnsmessage.TypeCNAME,
			Class: dnsmessage.ClassINET,
		},
	}
	dnsQuery := dnsMsg{
		msg: dnsMessage,
	}

	response, err := dnsQuery.sendQuery(dnsServer)
	if err != nil {
		return "", err
	}

	if len(response.Answers) == 0 || response.Answers[0].Header.Type != dnsmessage.TypeCNAME {
		return "", nil
	}

	foundCNAME := response.Answers[0].Body.(*dnsmessage.CNAMEResource).CNAME.String()

	return foundCNAME, nil
}

func DnsQueryA(domain string, dnsServer string) ([]string, error) {
	// Create a DNS message for an A record lookup (IPv4)
	var dnsMessage dnsmessage.Message
	dnsMessage.Header.RecursionDesired = true
	dnsMessage.Questions = []dnsmessage.Question{
		{
			Name:  dnsmessage.MustNewName(domain),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		},
	}

	dnsQuery := dnsMsg{
		msg: dnsMessage,
	}

	response, err := dnsQuery.sendQuery(dnsServer)
	if err != nil {
		return nil, err
	}

	// Collect IP addresses from the answer section
	var ips []string
	for _, answer := range response.Answers {
		if answer.Header.Type == dnsmessage.TypeA {
			ip := answer.Body.(*dnsmessage.AResource).A
			ips = append(ips, net.IP(ip[:]).String())
		}
	}

	return ips, nil
}
