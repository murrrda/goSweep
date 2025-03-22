package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"

	"github.com/murrrda/goSweep/pkg/dns"
	"github.com/murrrda/goSweep/pkg/output"
	"github.com/murrrda/goSweep/pkg/portscan"
	"github.com/murrrda/goSweep/pkg/sweep"
	"github.com/murrrda/goSweep/pkg/utils"
	"github.com/urfave/cli/v3"
)

func hasAdminPrivileges() bool {
	switch runtime.GOOS {
	case "linux", "darwin": // Unix-based OS (Linux, macOS)
		return os.Geteuid() == 0
	case "windows": // Windows
		return true
	default:
		return false
	}
}

func main() {
	var formatter output.Formatter
	cmd := &cli.Command{
		Name:                  "goSweep",
		Usage:                 "Command-line tool for network scanning",
		Suggest:               true,
		EnableShellCompletion: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "More detailed output",
			},
			&cli.BoolFlag{
				Name:  "no-color",
				Usage: "Disable colorful output, recommended when writing to file",
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
					if cmd.Bool("no-color") {
						formatter = &output.NoColorFormatter{
							Verbose: cmd.Bool("verbose"),
						}
					} else {
						formatter = &output.ColorFormatter{
							Verbose: cmd.Bool("verbose"),
						}
					}

					// we need sudo privileges for port scan
					if !hasAdminPrivileges() {
						formatter.Error("Not running with sudo or as root.")
						os.Exit(1)
					}

					host := cmd.String("target")
					portRange := cmd.String("port-range")
					startPort, endPort, err := utils.ParsePortRange(portRange)
					if err != nil {
						return fmt.Errorf("%v", err.Error())
					}

					// start scan
					portscan.TcpScan(host, startPort, endPort, formatter)
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
					&cli.StringFlag{
						Name:     "servers",
						Aliases:  []string{"s"},
						Required: false,
						Usage:    "Newline separated list of DNS servers to use",
					},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Bool("no-color") {
						formatter = &output.NoColorFormatter{
							Verbose: cmd.Bool("verbose"),
						}
					} else {
						formatter = &output.ColorFormatter{
							Verbose: cmd.Bool("verbose"),
						}
					}

					dns.SubdomainDiscovery(dns.DnsInput{
						Domain:         cmd.String("domain"),
						SubdomainsFile: cmd.String("wordlist"),
						ServersFile:    cmd.String("servers"),
					}, formatter)
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
					if cmd.Bool("no-color") {
						formatter = &output.NoColorFormatter{
							Verbose: cmd.Bool("verbose"),
						}
					} else {
						formatter = &output.ColorFormatter{
							Verbose: cmd.Bool("verbose"),
						}
					}

					// we need sudo privileges for port scan
					if !hasAdminPrivileges() {
						formatter.Error("Not running with sudo or as root.")
						os.Exit(1)
					}

					sweep.PingSweep(cmd.String("network"), formatter)
					return nil
				},
			},
		},
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
