package ldap

import (
	"strings"

	"github.com/emperorcow/go-netscan/scanners"
	"gopkg.in/ldap.v2"
)

// This is our scanner and does all the work from the main
type Scanner struct{}

// Returns the name of this scanner
func (this Scanner) Name() string {
	return "ldap"
}

// Returns a description of this scanner
func (this Scanner) Description() string {
	return "Lightweight Directory Access Protocol (LDAP)"
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
	// Add port 389 to the target if we didn't get a port from the user.
	if !strings.Contains(target, ":") {
		target = target + ":389"
	}

	// Let's assume that we connected successfully and declare the data as such, we can edit it later if we failed
	result := scanners.Result{
		Host:    target,
		Auth:    cred,
		Message: "Successfully bound to directory",
		Status:  true,
		Output:  "",
	}

	conn, err := ldap.Dial("tcp", target)
	// Return if we got an error on our setup of our credentials.
	if err != nil {
		result.Message = err.Error()
		result.Status = false
	}
	defer conn.Close()

	// Bind to the LDAP server and get a connection
	err = conn.Bind(cred.Account, cred.AuthData)
	if err != nil {
		result.Message = err.Error()
		result.Status = false
	}

	// If we didn't get an error and we have a query to execute then do it.
	if err == nil && cmd != "" {
		result.Output, err = this.executeQuery(conn, cmd)
		if err != nil {
			// If we got an error, let's give the user some output.
			result.Output = "Query Error: " + err.Error()
		}
	}

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result
}

// Runs an LDAP query on an existing connection and then returns the output as a string
func (this Scanner) executeQuery(connection *ldap.Conn, query string) (string, error) {
	return "", nil
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return &Scanner{}
}
