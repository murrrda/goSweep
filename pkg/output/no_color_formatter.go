// pkg/output/no_color_formatter.go
package output

import (
	"fmt"
)

type NoColorFormatter struct {
	Verbose bool
}

func (f *NoColorFormatter) Header(date string) {
	fmt.Println("<============================================================>")
	fmt.Printf("GoSweep Report - Generated at %s\n", date)
}

func (f *NoColorFormatter) Info(message string) {
	fmt.Println(message)
}

func (f *NoColorFormatter) Success(message string) {
	fmt.Println(message)
}

func (f *NoColorFormatter) Warning(message string) {
	fmt.Println(message)
}

func (f *NoColorFormatter) Error(message string) {
	fmt.Println(message)
}

func (f *NoColorFormatter) Result(result string) {
	fmt.Println(result)
}

func (f *NoColorFormatter) Footer() {
	fmt.Println("<============================================================>")
}

func (f *NoColorFormatter) GetString(s string) string {
	return s
}

func (f *NoColorFormatter) IsVerbose() bool {
	return f.Verbose
}
