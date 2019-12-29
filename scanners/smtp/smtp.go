package smtp

import (
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/emperorcow/go-netscan/scanners"
)

// This is our scanner and does all the work from the main
type Scanner struct{}

// Returns the name of this scanner
func (this Scanner) Name() string {
	return "smtp"
}

// Returns a description of this scanner
func (this Scanner) Description() string {
	return "Simple Mail Transfer Protocol (SMTP)"
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
	// Check our target and see if the default port is there, if not we include it.
	if !strings.Contains(target, ":") {
		target = target + ":25"
	}

	// Let's assume that we connected successfully and declare the data as such, we can edit it later if we failed
	result := scanners.Result{
		Host:    target,
		Auth:    cred,
		Message: "Successfully connected",
		Status:  true,
		Output:  "",
	}

	// Depending on the authentication type, run the correct connection function
	switch cred.Type {
	case "basic":
		// Set up authentication information.
		auth := sasl.NewPlainClient("", cred.Account, cred.AuthData)

		// Connect to the server, authenticate, set the sender and recipient,
		// and send the email all in one step.
		to := []string{cred.Account}
		msg := strings.NewReader("To: " + cred.Account + "\r\n" +
			"Subject: go-netscan test!\r\n" +
			"\r\n" +
			"This is a test email.\r\n")
		err := smtp.SendMail(target, auth, cred.Account, to, msg)
		if err != nil {
			result.Message = err.Error()
			result.Status = false
		}

	}

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return &Scanner{}
}
