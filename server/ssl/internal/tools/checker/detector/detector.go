package detector

type Confidence string

const (
	High   Confidence = "high"
	Medium Confidence = "medium"
	Low    Confidence = "low"
)

type Result struct {
	Name       string
	Vendor     string
	Confidence Confidence
	Evidence   []string
	Category   string // cdn, webserver, app, cloud
}

type Detector interface {
	Name() string
	Detect([]*Probe) *Result
}
