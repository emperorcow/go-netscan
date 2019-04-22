package inputs

import "github.com/emperorcow/go-netscan/scanners"

// All of our inputs must be sent together.
type Data struct {
	Target string
	Cred   scanners.Credential
}

// A interface to allow us to write input handlers that do things different ways
// We have an init function that we use to pre-process whatever data we want
// and then a Run function which will be started in a go-routine and should
// pass InputData's into the channel for our scanners.
type Handler interface {
	// Provide a basic description of the handler
	Description() string
	// Get the input channel
	Chan() chan Data
	// Add a new target to the handler
	AddTarget(string) error
	// Add a new credential to the handler
	AddCred(scanners.Credential) error
	// Actually run and provide data to our channel, will be run in a goroutine so
	// be prepared!
	Run()
}
