package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/murrrda/goSweep/pkg/dns"
	"github.com/murrrda/goSweep/pkg/portscan"
	"github.com/murrrda/goSweep/pkg/sweep"
	"github.com/murrrda/goSweep/pkg/utils"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:                  "goSweep",
		Usage:                 "Command-line tool for network scanning",
		Suggest:               true,
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
			},
		},
		Commands: []*cli.Command{
			{
				Name:    "ps",
				Usage:   "Perform a port scan",
				Suggest: true,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "target",
						Aliases:  []string{"t"},
						Required: true,
						Usage:    "The IP address or domain of the target",
					},
					&cli.StringFlag{
						Name:        "port-range",
						Aliases:     []string{"p"},
						Value:       "1:1024",
						DefaultText: "1:1024",
						Usage:       "The range of ports to scan",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					host := cmd.String("target")
					portRange := cmd.String("port-range")
					startPort, endPort, err := utils.ParsePortRange(portRange)
					if err != nil {
						return fmt.Errorf("%v", err.Error())
					}

					ips, err := net.LookupIP(host)
					if err != nil {
						return fmt.Errorf("%v", err.Error())
					}
					ip := ips[0].To4().String()

					// start scan
					portscan.TcpScan(host, ip, startPort, endPort)
					return nil
				},
			},
			{
				Name:    "dns",
				Suggest: true,
				Usage:   "Perform DNS subdomain Enumeration",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "domain",
						Aliases:  []string{"d"},
						Required: true,
						Usage:    "The domain of the target",
					},
					&cli.StringFlag{
						Name:     "wordlist",
						Aliases:  []string{"w"},
						Required: true,
						Usage:    "Path to newline separated file of subdomains",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					dns.SubdomainDiscovery(dns.DnsInput{
						Domain: cmd.String("domain"),
						File:   cmd.String("wordlist"),
					})
					return nil
				},
			},
			{
				Name:    "sweep",
				Suggest: true,
				Usage:   "Host discovery scan",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "network",
						Aliases:  []string{"n"},
						Required: true,
						Usage:    "Network to sweep provided in CIDR notation (e.g., 192.168.1.0/24).",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					sweep.PingSweep(cmd.String("network"))
					return nil
				},
			},
		},
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
