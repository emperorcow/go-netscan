package winrm

import (
	"bytes"
	"fmt"
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
func (this *winrmScanner) Prepare(creds []scanners.Credential, cmd string, outChan chan scanners.Result) error {
	// Load out output channel and command
	this.out = outChan
	this.cmd = cmd
	this.creds = creds
	return nil
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this winrmScanner) Scan(target string) {
	fmt.Printf("--- SCAN start\n")
	// Add port if the user dosn't provide. Default for basic auth winrm is 5985
	if !strings.Contains(target, ":") {
		target = target + ":5985"
	}

	// Vars to hold our winrmScanner connection and any erros
	for _, cred := range this.creds {
		fmt.Printf("--- CRED: %+v\n", cred)

		var err error
		var client *winrm.Client

		// Depending on the authentication type, run the correct connection function
		switch cred.Type {
		case "basic":
			client, err = this.basicConnect(cred.Account, target, cred.AuthData)
		}

		fmt.Printf("--- CLIENT: %+v\n", client)

		// Let's assume we connect succesfully
		result := scanners.Result{
			Host:    target,
			Message: "Succesfully connected",
			Status:  true,
			Output:  "",
		}

		// Create a shell on the object, making a connection to the system
		shell, err := client.CreateShell()
		fmt.Printf("--- SHELL: %+v\n", shell)
		if err != nil {
			result.Message = err.Error()
			result.Status = false
		} else {
			defer shell.Close() // We'll be good and close our connection when done
		}

		// if we didn't get an error and we have a command ot run, let's do it.
		if err == nil && this.cmd != "" {
			fmt.Printf("--- CMD: %s\n", this.cmd)
			// Execute the command
			result.Output, err = this.executeCommand(this.cmd, shell)
			if err != nil {
				// If we got an error let's let the user know
				result.Output = "Script Error: " + err.Error()
			}
		} else {
			fmt.Printf("--- CMD: NONE RUN\n")
		}

		fmt.Printf("--- RES: %+v\n\n", result)

		// Finally pass results to the outChan
		this.out <- result
	}
	fmt.Printf("--- SCAN done\n")
}

// Executes a command on a winrm client connection, returns an error if there is one
func (this winrmScanner) executeCommand(cmd string, shell *winrm.Shell) (string, error) {
	// Execute our command on the connection we have.
	command, err := shell.Execute(cmd)
	if err != nil {
		return "", err
	}

	// We need some buffers for STDOUT and STDERR
	var outWriter, errWriter bytes.Buffer

	// This waitgroup is to sync up the output buffers routines
	var wg sync.WaitGroup
	// We have two waits, one each for STDOUT and STDERR
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(&outWriter, command.Stdout)
	}()
	go func() {
		defer wg.Done()
		io.Copy(&errWriter, command.Stderr)
	}()

	// We'll wait for the command to finish and both buffer routines to finish before we move on.
	command.Wait()
	wg.Wait()

	// Let's get the strings from our buffers and join them
	output := outWriter.String() + errWriter.String()

	// Finally we can close up and return
	return output, err
}

// This function builds out a WinRM Client struct for us to then use to actually connect later.
func (this winrmScanner) basicConnect(user, host, pass string) (*winrm.Client, error) {
	// Split the host into host/ip and port
	tz := strings.Split(host, ":")
	// Get our two variables
	tzHost, tzPort := tz[0], tz[1]
	// Convert to the port into an integer
	tzPortInt, _ := strconv.Atoi(tzPort)
	// Create a new endpoint struct with our port: NewEndpoint(host string, port int, https bool, insecure bool, Cacert, cert, key []byte, timeout time.Duration)
	endpoint := winrm.NewEndpoint(tzHost, tzPortInt, false, false, nil, nil, nil, 0)

	// Build our auth to the object, does not connect yet.
	client, err := winrm.NewClient(endpoint, user, pass)

	return client, err
}

// Create a new scanner
func NewScanner() scanners.Scanner {
	return &winrmScanner{}
}
