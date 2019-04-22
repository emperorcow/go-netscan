package smb

import (
	"strconv"
	"strings"

	"github.com/emperorcow/go-netscan/scanners"
	"github.com/stacktitan/smb/smb"
)

// This is our scanner and does all the work from the main
type Scanner struct{}

// Returns the name of this scanner
func (this Scanner) Name() string {
	return "smb"
}

// Returns a description of this scanner
func (this Scanner) Description() string {
	return "Server Message Block (SMB)"
}

// Returns the types of auth we support in this scanner
func (this Scanner) SupportedAuthentication() []string {
	return []string{"basic"}
}

// Returns some examples on how to configure the auth info
func (this Scanner) SupportedAuthenticationExample() map[string]string {
	return map[string]string{
		"basic": "USERNAME,PASSWORD",
	}
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this Scanner) Scan(target, cmd string, cred scanners.Credential, outChan chan scanners.Result) {
	opts := smb.Options{
		Host:     target,
		Port:     445,
		User:     cred.Account,
		Domain:   ".",
		Password: cred.AuthData,
	}

	// Check our target and see if it contains a port, if so parse it out
	if strings.Contains(target, ":") {
		targetInfo := strings.Split(target, ":")
		opts.Host = targetInfo[0]
		opts.Port, _ = strconv.Atoi(targetInfo[1])
	}

	// Check and see if we have a logon domain in our user (DOMAIN\USER)
	if strings.Contains(cred.Account, "\\") {
		logonInfo := strings.Split(cred.Account, "\\")
		opts.Domain = logonInfo[0]
		opts.User = logonInfo[1]
	}

	// Let's assume that we connected successfully and declare the data as such, we can edit it later if we failed
	result := scanners.Result{
		Host:    target,
		Auth:    cred,
		Message: "Successfully connected",
		Status:  true,
		Output:  "",
	}

	session, err := smb.NewSession(opts, false)
	// Return if we got an error on our setup of our credentials.
	if err != nil {
		result.Message = err.Error()
		result.Status = false
	}
	defer session.Close()

	// Here we should actually connect to the protocol and see, example:
	if session.IsAuthenticated {
		result.Message = "Logon failed."
		result.Status = false
	}

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return &Scanner{}
}
