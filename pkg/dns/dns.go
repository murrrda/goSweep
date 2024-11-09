package dns

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

// time in seconds to wait before sending
// next dns query (per server)
var TIMEOUT = 1

var dnsServerPool = [...]net.IP{
	net.ParseIP("8.8.8.8"),        // google
	net.ParseIP("1.1.1.1"),        // cloudflare
	net.ParseIP("9.9.9.9"),        // quad9
	net.ParseIP("208.67.222.222"), // open DNS
	net.ParseIP("84.200.69.80"),   // DNS.Watch
	net.ParseIP("91.239.100.100"), // UncensoredDNS
}

type result struct {
	domain  string
	resulIp *net.IP
	dns     *net.IP
	hit     bool
}

type target struct {
	dnsServer     *net.IP
	domain        string
	subdomainChan chan string
	resultChan    chan result
}

type Input struct {
	Domain string
	File   string
}

func SubdomainDiscovery(input Input) {
	if _, err := net.LookupIP(input.Domain); err != nil {
		log.Fatal(err.Error())
	}

	wordlist, err := os.Open(input.File)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer wordlist.Close()

	// scanner for reading file
	scanner := bufio.NewScanner(wordlist)

	subdomainChan := make(chan string) // will close after all values are sent to chan

	resultChan := make(chan result)
	defer close(resultChan)

	// number of workers = number of dns servers
	// each goroutine gets specific dns server
	for _, v := range dnsServerPool {
		go worker(target{
			dnsServer:     &v,
			domain:        input.Domain,
			subdomainChan: subdomainChan,
			resultChan:    resultChan,
		})
	}

	// nSubdomains := 0

	// sledecu funkciju izvrsiti u ovoj goroutine da bi znali koliko imamo subdomains i da znamo koliko rezultata ocekujemo
	// alternativa je da koristim waitgroups
	// read file line by line and put it in chan
	go func() {
		defer close(subdomainChan) // after this routine there is no more sending value to resultChan so we can close safely
		for scanner.Scan() {
			subdomainChan <- scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err.Error())
		}
	}()

}

func worker(t target) {
	fmt.Println(t.dnsServer)
	for subdomain := range t.subdomainChan {
		fmt.Println(subdomain)
		//TODO: make query and print results

		t.resultChan <- result{
			domain: t.domain,
			dns:    t.dnsServer,
			hit:    false,
		}
		time.Sleep(1 * time.Second)
	}
}
