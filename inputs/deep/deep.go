package deep

import (
	"github.com/emperorcow/go-netscan/inputs"
	"github.com/emperorcow/go-netscan/scanners"
)

type Handler struct {
	in    chan inputs.Data
	hosts []string
	creds []scanners.Credential
}

// Tell everyone what wide actually means
func (this *Handler) Description() string {
	return "Runs all credentials on one host before going to the next."
}

// Get the data channel
func (this *Handler) Chan() chan inputs.Data {
	return this.in
}

// Add a target to our handler, we can't really error on append here so
// we'll always be nil in this handler.
func (this *Handler) AddTarget(target string) error {
	this.hosts = append(this.hosts, target)
	return nil
}

// Add a new credential to the handler, same as above, can't really error
func (this *Handler) AddCred(cred scanners.Credential) error {
	this.creds = append(this.creds, cred)
	return nil
}

// Loops through credentials one at a time and does all hosts for each, this will
// limit the number of attempts we have on a host in short timeframes
func (this *Handler) Run() {
	for _, host := range this.hosts {
		for _, cred := range this.creds {
			// Add it to our channel
			this.in <- inputs.Data{
				Target: host,
				Cred:   cred,
			}
		}
	}
}

// Creates a new scanner for us to add to the main loop, we'll take a buffer size
// to limit how many we send at a time.
func NewHandler() inputs.Handler {
	return &Handler{
		in:    make(chan inputs.Data, 20),
		hosts: []string{},
		creds: []scanners.Credential{},
	}
}
