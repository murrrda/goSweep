package dns

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/murrrda/goSweep/pkg/output"
	"github.com/murrrda/goSweep/pkg/utils"
)

// time in seconds to wait before sending
// next dns query (per server)
var DELAY = 200 * time.Millisecond

// this structs holds domain and wildcard lookup results
type subWCard struct {
	A      bool
	AAAA   bool
	CNAME  bool
	domain string
}

type targetDNS struct {
	resultChan  chan ResultDNS
	domainCh    chan subWCard
	timeoutChan chan subWCard
	dnsServer   *net.IP
}

type DnsInput struct {
	Domain         string
	SubdomainsFile string
	ServersFile    string
}

// SubdomainDiscovery orchestrates the subdomain enumeration process using multiple DNS servers.
//
// This function manages the entire workflow for subdomain discovery, including feeding input
// subdomains to workers, handling DNS queries, processing results, and managing retries for timeouts.
// It leverages a pool of DNS servers to perform lookups in parallel and outputs results in the
// specified format.
//
// Parameters:
//
//	input (DnsInput): Contains the domain name and the file with a list of subdomains to query.
//
//	formatter (output.Formatter): Used to format and log output, including successes and errors.
//
// Example:
//
//	input := DnsInput{Domain: "example.com", File: "subdomains.txt"}
//	formatter := output.ColorFormatter{
//		Verbose: false,
//	}
//	SubdomainDiscovery(input, formatter)
//
// Errors:
//
//   - Non-fatal errors, such as timeout errors during DNS lookups, are handled gracefully by
//     piping the affected subdomains to retry workers for reprocessing.
//   - Fatal errors, such as a failure to read the input file, result in immediate termination
//     of the program after logging an appropriate error message via the formatter.
//
// Returns:
//
//	void: The function does not return any value. It outputs results directly via the formatter.
func SubdomainDiscovery(input DnsInput, formatter output.Formatter) {
	printStart(input, formatter)
	targetDomain := canonicalizeDomain(input.Domain)
	dnsServers := initializeDnsServers(input)

	domainCh := make(chan subWCard, 100)
	timeoutCh := make(chan subWCard, 10)
	resCh := make(chan ResultDNS, 10)

	var producerWG sync.WaitGroup
	var retryWG sync.WaitGroup
	var resultWG sync.WaitGroup

	// spawn retry workers
	// Retry happens when we get timeout error
	for _, v := range dnsServers {
		retryWG.Add(1)
		go retryWorker(&retryWG, targetDNS{
			dnsServer:   &v,
			domainCh:    domainCh,
			resultChan:  resCh,
			timeoutChan: timeoutCh,
		}, formatter)
	}

	// Spawn producer workers (one per DNS server)
	for _, v := range dnsServers {
		producerWG.Add(1)
		go prodWorker(&producerWG, targetDNS{
			dnsServer:   &v,
			domainCh:    domainCh,
			resultChan:  resCh,
			timeoutChan: timeoutCh,
		}, formatter)
	}

	// send subdomains to workers
	go func() {
		defer close(domainCh) // after this routine there is no more sending value to resultChan so we can close safely
		if err := checkSubdomains(input.SubdomainsFile, dnsServers, targetDomain, domainCh, formatter); err != nil {
			formatter.Error(err.Error())
			os.Exit(1)
		}
	}()

	// goroutine to read and print results from workers
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

func lookupRecords(subdomain subWCard, dnsServer net.IP) (ResultDNS, error) {
	dnsServerString := dnsServer.String()
	r := ResultDNS{
		subdomain:   subdomain.domain,
		foundRecord: false,
	}

	if subdomain.A {
		A, err := utils.DnsQueryA(subdomain.domain, dnsServerString)
		if err != nil {
			// sleep only if timeout error
			if errors.Is(err, utils.ErrDNSTimeout) {
				time.Sleep(DELAY)
			}
			return ResultDNS{}, err
		}
		if len(A) > 0 {
			r.A = A
			r.foundRecord = true
		}
		time.Sleep(DELAY)
	}

	if subdomain.AAAA {
		AAAA, err := utils.DnsQueryAAAA(subdomain.domain, dnsServerString)
		if err != nil {
			// sleep only if timeout error
			if errors.Is(err, utils.ErrDNSTimeout) {
				time.Sleep(DELAY)
			}
			return ResultDNS{}, err
		}
		if len(AAAA) > 0 {
			r.AAAA = AAAA
			r.foundRecord = true
		}
		time.Sleep(DELAY)
	}

	// if we found A or AAAA record, we don't need to lookup CNAME records so we return early
	if r.foundRecord {
		return r, nil
	}

	// if not we continue digging
	if subdomain.CNAME {
		cnames, err := lookupCnameChain(subdomain.domain, dnsServerString)
		if err != nil {
			return ResultDNS{}, err
		}
		if len(cnames) > 0 {
			r.foundRecord = true
			r.cnames = cnames
		}
	}

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
		time.Sleep(DELAY)
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

func prodWorker(wg *sync.WaitGroup, t targetDNS, formatter output.Formatter) {
	defer wg.Done()
	for subdomain := range t.domainCh {
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

func retryWorker(wg *sync.WaitGroup, t targetDNS, formatter output.Formatter) {
	defer wg.Done()
	for subdomain := range t.timeoutChan {
		res, err := lookupRecords(subdomain, *t.dnsServer)
		if err != nil {
			formatter.Error(err.Error())
			continue
		}

		t.resultChan <- res
	}

}

// CheckSubdomains reads subdomain candidates from a wordlist file and coordinates workers
// to validate them against DNS wildcards.
//
// Workers (one per DNS server in dnsServers) perform concurrent wildcard validation
// using a shared cache to avoid redundant DNS lookups. Processed subdomains with their
// wildcard status are sent to domainCh by the workers.
func checkSubdomains(wordlistPath string, dnsServers []net.IP, targetDomain string, domainCh chan<- subWCard, formatter output.Formatter) error {
	wordlist, err := os.Open(wordlistPath)
	if err != nil {
		return err
	}
	defer wordlist.Close()

	// channel to send subdomains to wildcard lookup workers
	var entries = make(chan string, 100)
	// map to store wildcard lookup results
	var wCardCache sync.Map

	var wg sync.WaitGroup
	for range dnsServers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wCardLookupWorker(entries, domainCh, targetDomain, &wCardCache, formatter)
		}()
	}

	// scanner for reading file
	scanner := bufio.NewScanner(wordlist)
	go func() {
		defer close(entries)
		for scanner.Scan() {
			entries <- scanner.Text()
		}
	}()

	wg.Wait()

	return scanner.Err()
}

// wCardLookupWorker is one of the wildcard lookup workers
func wCardLookupWorker(entries <-chan string, domainCh chan<- subWCard, targetDomain string, wCardCache *sync.Map, formatter output.Formatter) {
	for subdomain := range entries {
		v := wCardLookup(subdomain, targetDomain, wCardCache, formatter)
		v.domain = subdomain + "." + targetDomain
		domainCh <- v
	}
}

// wCardLookup checks if the subdomain has wildcard records
func wCardLookup(subdomain, targetDomain string, wCardCache *sync.Map, formatter output.Formatter) subWCard {
	swp := wildcardDeepestSubdomain(subdomain)
	randDomain := "unlikely-" + strconv.Itoa(time.Now().Nanosecond()) + "-" + subdomain + "." + targetDomain

	if val, ok := wCardCache.Load(swp); ok {
		return val.(subWCard)
	}

	rec := subWCard{}
	_, err := net.LookupIP(randDomain)
	if err != nil {
		rec.A = true
		rec.AAAA = true
	} else {
		rec.A = false
		rec.AAAA = false
	}
	time.Sleep(DELAY / 3)

	if _, err = net.LookupCNAME(randDomain); err != nil {
		rec.CNAME = true
	} else {
		rec.CNAME = false
	}

	if existing, loaded := wCardCache.LoadOrStore(swp, rec); loaded {
		return existing.(subWCard)
	}
	if !rec.A || !rec.AAAA || !rec.CNAME {
		formatter.Warning(fmt.Sprintf("Wildcard DNS detected: %v\nOmitting all lookups that match %v", swp+"."+targetDomain, swp+"."+targetDomain))
	}

	return rec
}

func wildcardDeepestSubdomain(input string) string {
	// Check if there is a dot in the input
	firstDot := strings.Index(input, ".")
	if firstDot == -1 {
		// No dot found, return "*"
		return "*"
	}

	// Return "*." followed by everything after the first dot
	return "*." + input[firstDot+1:]
}

func initializeDnsServers(input DnsInput) []net.IP {
	dnsServers := []net.IP{
		net.ParseIP("8.8.8.8"),        // google
		net.ParseIP("1.1.1.1"),        // cloudflare
		net.ParseIP("9.9.9.9"),        // quad9
		net.ParseIP("208.67.222.222"), // open DNS
	}

	if input.ServersFile != "" {
		file, err := os.Open(input.ServersFile)
		if err != nil {
			fmt.Println("Error opening file:", err)
			os.Exit(1)
		}
		defer file.Close()
		// clear defaults
		dnsServers = []net.IP{}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ip := net.ParseIP(scanner.Text())
			if ip != nil {
				dnsServers = append(dnsServers, ip)
			}
		}
	}

	return dnsServers
}

func printStart(input DnsInput, formatter output.Formatter) {
	formatter.Header(time.Now().Format("January 02, 2006 15:04:05 MST"))
	formatter.Info("Beggining Subdomain Discovery...\n")
	formatter.Info(fmt.Sprintf("Domain: %v", input.Domain))
	formatter.Info(fmt.Sprintf("Wordlist: %v", input.SubdomainsFile))
	formatter.Footer()
}
