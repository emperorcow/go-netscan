package vnc

import (
	"context"
	"net"
	"strings"

	"github.com/emperorcow/go-netscan/scanners"
	vnc "github.com/kward/go-vnc"
)

// This is our scanner and does all the work from the main
type Scanner struct{}

// Returns the name of this scanner
func (this Scanner) Name() string {
	return "vnc"
}

// Returns a description of this scanner
func (this Scanner) Description() string {
	return "VNC Virtual Network Computing (VNC))"
}

// Returns the types of auth we support in this scanner
func (this Scanner) SupportedAuthentication() []string {
	return []string{"basic"}
}

// Returns some examples on how to configure the auth info
func (this Scanner) SupportedAuthenticationExample() map[string]string {
	return map[string]string{
		"basic": "PASSWORD",
	}
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this Scanner) Scan(target, cmd string, cred scanners.Credential, outChan chan scanners.Result) {
	// Check our target and see if the default port is there, if not we include it.
	if !strings.Contains(target, ":") {
		target = target + ":1234"
	}

	// Let's assume that we connected successfully and declare the data as such, we can edit it later if we failed
	result := scanners.Result{
		Host:    target,
		Auth:    cred,
		Message: "Successfully connected",
		Status:  true,
		Output:  "",
	}

	var pass string

	// Depending on the authentication type, run the correct connection function
	switch cred.Type {
	case "basic":
		pass = cred.AuthData
	}

	nc, err := net.Dial("tcp", target)
	// Negotiate connection with the vnc server
	vcc := vnc.NewClientConfig(pass)
	_, err = vnc.Connect(context.Background(), nc, vcc)

	// Here we should actually connect to the protocol and see, example:
	// session, err := tp.connect(cred.Account, cred.AuthData, target)
	// If we got an error, let's set the data properly
	if err != nil {
		result.Message = err.Error()
		result.Status = false
	}

	// If we didn't get an error and we have a command to run, let's do it.
	if err == nil && cmd != "" {
		// Execute the command
		// result.Output, err = this.executeCommand(cmd, session)
		if err != nil {
			// If we got an error, let's give the user some output.
			result.Output = "Script Error: " + err.Error()
		}
	}

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return &Scanner{}
}
