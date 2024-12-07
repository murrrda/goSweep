package output

import (
	"fmt"
)

type ColorFormatter struct {
	Verbose bool
}

func (f *ColorFormatter) Header(date string) {
	fmt.Println("\033[1;34m<============================================================>\033[0m")
	fmt.Printf("GoSweep Report - Generated at %s\n", date)
}

func (f *ColorFormatter) Info(message string) {
	fmt.Println(message)
}

func (f *ColorFormatter) Success(message string) {
	fmt.Printf("\033[1;32m%s\033[0m\n", message)
}

func (f *ColorFormatter) Warning(message string) {
	fmt.Printf("\033[1;33m%s\033[0m\n", message)
}

func (f *ColorFormatter) Error(message string) {
	fmt.Printf("\033[1;31m%s\033[0m\n", message)
}

func (f *ColorFormatter) Footer() {
	fmt.Println("\033[1;34m<============================================================>\033[0m")
}

func (f *ColorFormatter) GetString(s string) string {
	return fmt.Sprintf("\033[1;32m%s\033[0m", s)
}

func (f *ColorFormatter) IsVerbose() bool {
	return f.Verbose
}
