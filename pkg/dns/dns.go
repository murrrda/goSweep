package dns

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/murrrda/goSweep/pkg/utils"
)

// time in seconds to wait before sending
// next dns query (per server)
var DELAY = 300 * time.Millisecond

var dnsServerPool = [...]net.IP{
	net.ParseIP("8.8.8.8"),        // google
	net.ParseIP("1.1.1.1"),        // cloudflare
	net.ParseIP("9.9.9.9"),        // quad9
	net.ParseIP("208.67.222.222"), // open DNS
}

type result struct {
	// evaluated subdomain
	subdomain string
	// records
	A           []string
	AAAA        []string
	MX          []string
	cnames      []string
	foundRecord bool
}

func (r result) String() string {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("Domain: %s\n", r.subdomain))
	if len(r.A) > 0 {
		builder.WriteString("\tA records:\n")
		for _, ip := range r.A {
			builder.WriteString(fmt.Sprintf("\t\t%s\n", ip))
		}
	}
	if len(r.AAAA) > 0 {
		builder.WriteString("\tAAAA records:\n")
		for _, ip := range r.AAAA {
			builder.WriteString(fmt.Sprintf("\t\t%s\n", ip))
		}
	}
	if len(r.MX) > 0 {
		builder.WriteString("\tMX records:\n")
		for _, mx := range r.MX {
			builder.WriteString(fmt.Sprintf("\t\t%s\n", mx))
		}
	}
	if len(r.cnames) > 0 {
		builder.WriteString("\tCNAME records:\n\t\t")
		n := len(r.cnames)
		for i := 0; i < n-1; i++ {
			builder.WriteString(r.cnames[i] + " -> ")

		}
		builder.WriteString(r.cnames[n-1] + "\n")
	}

	return builder.String()
}

type target struct {
	resultChan    chan result
	subdomainChan chan string
	dnsServer     *net.IP
	domain        string
}

type Input struct {
	Domain string
	File   string
}

// SubdomainDiscovery function
// input: domain, file
// output: none
// function will read file line by line and send subdomains to workers.
// workers will make dns query for each subdomain and print results
func SubdomainDiscovery(input Input) {
	domain := canonicalizeDomain(input.Domain)

	subdomainChan := make(chan string)
	resultChan := make(chan result)
	doneSignal := make(chan struct{}, 1)

	var wg sync.WaitGroup

	// number of workers = number of dns servers
	// each goroutine gets specific dns server
	for _, v := range dnsServerPool {
		wg.Add(1)
		go worker(&wg, target{
			dnsServer:     &v,
			domain:        domain,
			subdomainChan: subdomainChan,
			resultChan:    resultChan,
		})
	}

	wordlist, err := os.Open(input.File)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer wordlist.Close()

	// scanner for reading file
	scanner := bufio.NewScanner(wordlist)

	// send subdomains to workers
	go func() {
		defer close(subdomainChan) // after this routine there is no more sending value to resultChan so we can close safely
		for scanner.Scan() {
			sub := scanner.Text()
			subdomainChan <- sub + "." + domain
		}
		if err := scanner.Err(); err != nil {
			log.Fatal(err.Error())
		}
	}()

	// goroutine to read results from workers
	go func() {
		for r := range resultChan {
			if r.foundRecord {
				fmt.Println(r)
			}
		}
		doneSignal <- struct{}{}
	}()

	wg.Wait()
	close(resultChan)
	<-doneSignal
	close(doneSignal)
}

// canonicalizeDomain appends a trailing dot to the input domain if one is not already present.
// This is useful for ensuring the domain is in a canonical format as per DNS conventions.
//
// Parameters:
//
//	domain (string): The domain name to canonicalize.
//
// Returns:
//
//	string: The canonicalized domain with a trailing dot.
func canonicalizeDomain(domain string) string {
	if domain[len(domain)-1] == '.' {
		return domain
	}

	return domain + "."
}

func lookupRecords(subdomain string, dnsServer net.IP) (result, error) {
	dnsServerString := dnsServer.String()
	r := result{
		subdomain:   subdomain,
		foundRecord: false,
	}

	// lookup CNAME chain
	cnames, err := lookupCnameChain(subdomain, dnsServerString)
	if err != nil {
		return result{}, err
	}

	// if we actually found CNAME records, there is no reason to dig deeper
	if len(cnames) > 0 {
		r.foundRecord = true
		r.cnames = cnames
		return r, nil
	}

	// if not we continue digging

	A, err := utils.DnsQueryA(subdomain, dnsServerString)
	if err != nil {
		return result{}, err
	}
	if len(A) > 0 {
		r.A = A
		r.foundRecord = true
	}
	time.Sleep(DELAY)

	AAAA, err := utils.DnsQueryAAAA(subdomain, dnsServerString)
	if err != nil {
		return result{}, err
	}
	if len(AAAA) > 0 {
		r.AAAA = AAAA
		r.foundRecord = true
	}
	time.Sleep(DELAY)

	return r, nil
}

func lookupCnameChain(domain string, dnsServerString string) ([]string, error) {
	var cnames []string

	// send one query to check if there is CNAME record
	// this is mainly to prevent sending query for A record if cname does not exist
	cname, err := utils.DnsQueryCNAME(domain, dnsServerString)
	if err != nil {
		return nil, err
	}
	if len(cname) == 0 {
		return cnames, nil
	}
	cnames = append(cnames, cname)
	domain = cname

	// if there is cname record for the domain
	// we will follow the chain
	time.Sleep(DELAY)
	for {
		cname, err := utils.DnsQueryCNAME(domain, dnsServerString)
		if err != nil {
			return nil, err
		}
		time.Sleep(DELAY)
		if len(cname) == 0 {
			A, err := utils.DnsQueryA(domain, dnsServerString)
			if err != nil {
				return nil, err
			}
			if len(A) > 0 {
				cnames = append(cnames, A[0])
			}
			time.Sleep(DELAY)
			break
		}
		cnames = append(cnames, cname)
		domain = cname
	}
	return cnames, nil
}

func worker(wg *sync.WaitGroup, t target) {
	defer wg.Done()
	for subdomain := range t.subdomainChan {
		res, err := lookupRecords(subdomain, *t.dnsServer)
		if err != nil {
			log.Println(err.Error())
		}

		t.resultChan <- res
	}
}
