package dns

import (
	"fmt"
	"strings"

	"github.com/murrrda/goSweep/pkg/output"
)

type ResultDNS struct {
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

func (r ResultDNS) String(formatter output.Formatter) string {
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
