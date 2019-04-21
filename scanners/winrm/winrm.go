package winrm

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/emperorcow/go-netscan/scanners"
	"github.com/masterzen/winrm"
)

type winrmScanner struct {
	out   chan scanners.Result
	creds []scanners.Credential
	cmd   string
}

// Returns the name of this scanner
func (this winrmScanner) Name() string {
	return "winrm"
}

// Returns a description of the scanner
func (this winrmScanner) Description() string {
	return "Windows Remote Managment (WinRM)"
}

// Return the types of auth we support in  this scanner
func (this winrmScanner) SupportedAuthentication() []string {
	return []string{"basic"}
}

// Returns some examples of how to configure the auth info
func (this winrmScanner) SupportedAuthenticationExample() map[string]string {
	return map[string]string{
		"basic": "USERNAME,PASSWORD",
	}
}

// Gets out credentials
func (this winrmScanner) Prepare(creds []scanners.Credential, cmd string, outChan chan scanners.Result) error {
	// Load out output channel and command
	this.out = outChan
	this.cmd = cmd
	this.creds = creds
	return nil
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this winrmScanner) Scan(target string) {
	// Add port if the user dosn't provide. Default for basic auth winrm is 5985
	if !strings.Contains(target, ":") {
		target = target + ":5985"
	}

	// Vars to hold our winrmScanner connection and any erros
	for _, cred := range this.creds {
		var err error
		var connection *winrm.Client

		// Depending on the authentication type, run the correct connection function
		switch cred.Type {
		case "basic":
			_, connection, err = this.basicConnect(cred.Account, target, cred.AuthData)
		}

		// Let's assume we connect succesfully
		result := scanners.Result{
			Host:    target,
			Message: "Succesfully connected",
			Status:  true,
			Output:  "",
		}

		// If we got an error let's set it
		if err != nil {
			result.Message = err.Error()
			result.Status = false
		}

		// if we didn't get an error and we have a command ot run, let's do it.
		if err == nil && this.cmd != "" {
			// Execute the command
			result.Output, err = this.executeCommand(this.cmd, connection)
			if err != nil {
				// If we got an error let's let the user know
				result.Output = "Script Error: " + err.Error()
			}
		}

		// Finally pass results to the outChan
		this.out <- result
	}
}

// Executes a command on a winrm client connection, returns an error if there is one
func (this winrmScanner) executeCommand(cmd string, connection *winrm.Client) (string, error) {
	//Runs the command in the client
	output := new(bytes.Buffer)
	rpipe, wpipe := io.Pipe()

	wg := new(sync.WaitGroup)
	finchan := make(chan bool, 1)
	errchan := make(chan error, 1)

	wg.Add(1)

	go func() {
		defer wg.Done()
		_, err := connection.Run(cmd, wpipe, wpipe)
		if err != nil {
			errchan <- err
			return
		}

		finchan <- true
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(output, rpipe)
	}()

	wg.Wait()

	select {
	case err := <-errchan:
		return "", err
	case <-finchan:
		return output.String(), nil
	}
}

func (this winrmScanner) basicConnect(user, host, pass string) (*winrm.Endpoint, *winrm.Client, error) {
	// Split the host into host/ip and port
	tz := strings.Split(host, ":")
	tzh, tzp := tz[0], tz[1]
	tzpi, _ := strconv.Atoi(tzp)
	// tzh for host and tzp for port (tzpi is the int type of the port), default winrm is 5985 or 5986
	endpoint := winrm.NewEndpoint(tzh, tzpi, false, false, nil, nil, nil, 0)
	// auth to the endpoint
	client, err := winrm.NewClient(endpoint, user, pass)

	return endpoint, client, err
}

// Create a new scanner
func NewScanner() scanners.Scanner {
	return winrmScanner{}
}
