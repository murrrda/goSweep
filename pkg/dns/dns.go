package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

const dnsWorkers = 1000

func SubdomainDiscovery(domain, input string) {
	// validate domain
	_, err := net.LookupIP(domain)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// open wordlist
	wordlist, err := os.Open(input)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer wordlist.Close()

	words := make(chan string)
	scanner := bufio.NewScanner(wordlist)
	go func(*bufio.Scanner, *chan string) {
		for scanner.Scan() {
			words <- scanner.Text()
		}
	}(scanner, &words)

}

func worker() {}
