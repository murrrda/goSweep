package dns

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/murrrda/goSweep/pkg/output"
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
	// enumerated subdomain
	subdomain string
	// records
	A      []string
	AAAA   []string
	MX     []string
	cnames []string
	// true if we found any record
	foundRecord bool
}

func (r result) String(formatter output.Formatter) string {
	if !formatter.IsVerbose() {
		return "Found: " + r.subdomain
	}
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

type DNSTarget struct {
	resultChan    chan result
	subdomainChan chan string
	timeoutChan   chan string
	dnsServer     *net.IP
	domain        string
}

type DnsInput struct {
	Domain string
	File   string
}

func SubdomainDiscovery(input DnsInput, formatter output.Formatter) {
	printStart(input, formatter)
	domain := canonicalizeDomain(input.Domain)

	subdomainCh := make(chan string)
	timeoutCh := make(chan string)
	resCh := make(chan result)

	var producerWG sync.WaitGroup
	var retryWG sync.WaitGroup
	var resultWG sync.WaitGroup

	// spawn retry workers
	// Retry happens when we get timeout error
	for _, v := range dnsServerPool {
		retryWG.Add(1)
		go retryWorker(&retryWG, DNSTarget{
			dnsServer:     &v,
			domain:        domain,
			subdomainChan: subdomainCh,
			resultChan:    resCh,
			timeoutChan:   timeoutCh,
		}, formatter)
	}

	// Spawn producer workers (one per DNS server)
	for _, v := range dnsServerPool {
		producerWG.Add(1)
		go prodWorker(&producerWG, DNSTarget{
			dnsServer:     &v,
			domain:        domain,
			subdomainChan: subdomainCh,
			resultChan:    resCh,
			timeoutChan:   timeoutCh,
		}, formatter)
	}

	// send subdomains to workers
	go func() {
		defer close(subdomainCh) // after this routine there is no more sending value to resultChan so we can close safely
		if err := feedSubdomains(input.File, domain, subdomainCh); err != nil {
			formatter.Error(err.Error())
			os.Exit(1)
		}
	}()

	// goroutine to read results from workers
	resultWG.Add(1)
	go func() {
		defer resultWG.Done()
		for r := range resCh {
			if r.foundRecord {
				formatter.Success(r.String(formatter))
			}
		}
	}()

	producerWG.Wait()
	close(timeoutCh)

	retryWG.Wait()
	close(resCh)

	resultWG.Wait()

	formatter.Footer()
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

func prodWorker(wg *sync.WaitGroup, t DNSTarget, formatter output.Formatter) {
	defer wg.Done()
	for subdomain := range t.subdomainChan {
		res, err := lookupRecords(subdomain, *t.dnsServer)
		if err != nil {
			if errors.Is(err, utils.ErrDNSTimeout) {
				t.timeoutChan <- subdomain
			} else {
				formatter.Error(err.Error())
			}
			continue
		}

		t.resultChan <- res
	}
}

func retryWorker(wg *sync.WaitGroup, t DNSTarget, formatter output.Formatter) {
	defer wg.Done()
	for subdomain := range t.timeoutChan {
		fmt.Println(subdomain)
		res, err := lookupRecords(subdomain, *t.dnsServer)
		if err != nil {
			formatter.Error(err.Error())
			continue
		}

		t.resultChan <- res
	}
}

func feedSubdomains(filePath, domain string, subdomainChan chan<- string) error {
	wordlist, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer wordlist.Close()

	// scanner for reading file
	scanner := bufio.NewScanner(wordlist)
	for scanner.Scan() {
		sub := scanner.Text()
		subdomainChan <- sub + "." + domain
	}

	return scanner.Err()
}

func printStart(input DnsInput, formatter output.Formatter) {
	formatter.Header(time.Now().Format("January 02, 2006 15:04:05 MST"))
	formatter.Info("Beggining Subdomain Discovery...\n")
	formatter.Info(fmt.Sprintf("Domain: %v", input.Domain))
	formatter.Info(fmt.Sprintf("Wordlist: %v", input.File))
	formatter.Footer()
}
