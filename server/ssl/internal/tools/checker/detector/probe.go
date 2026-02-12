package detector

import "net/http"

type Probe struct {
	URL      string
	Method   string
	Response *http.Response
	Error    error
}
