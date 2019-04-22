package random

import (
	"math/rand"

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
	return "Loads all targets and credentials into memory and randomized a combined list"
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

// Loops through all of our inputs and builds a single large slice of inputs.Data
// that we can then shuffle and do randomly.  Large target lists will take a lot
// of memory.
func (this *Handler) Run() {
	// Place to hold our data
	temp := []inputs.Data{}

	// Loop through hosts and creds adding to the data slice
	for _, host := range this.hosts {
		for _, cred := range this.creds {
			temp = append(temp, inputs.Data{
				Target: host,
				Cred:   cred,
			})
		}
	}

	// Shuffle our slice
	for i := range temp {
		j := rand.Intn(i + 1)
		temp[i], temp[j] = temp[j], temp[i]
	}

	// Add it to our channel
	for _, target := range temp {
		this.in <- target
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
