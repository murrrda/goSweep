package dns

import (
	"net"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsMsg struct {
	msg dnsmessage.Message
}

func (d *dnsMsg) sendQuery(dnsServer string) (dnsmessage.Message, error) {
	packet, err := d.msg.Pack()
	if err != nil {
		return dnsmessage.Message{}, err
	}

	conn, err := net.Dial("udp", dnsServer+":53")
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer conn.Close()

	// Set a timeout for the connection
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return dnsmessage.Message{}, err
	}

	// Send the DNS query packet
	_, err = conn.Write(packet)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	// Read the response
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

func DnsQueryTypeMX(domain string, dnsServer string) ([]string, error) {
	// Create a DNS message for an A record lookup (IPv4)
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

func DnsQueryTypeAAAA(domain string, dnsServer string) ([]string, error) {
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
func DnsQueryTypeCNAME(domain string, dnsServer string) (string, error) {
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

func DnsQueryTypeA(domain string, dnsServer string) ([]string, error) {
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
