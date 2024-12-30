// pkg/output/formatter.go
package output

type Formatter interface {
	Header(date string)
	Info(message string)
	Success(message string)
	Warning(message string)
	Error(message string)
	Footer()
	GetString(s string) string
	IsVerbose() bool
}
