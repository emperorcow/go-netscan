package ssh

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

type SSH struct{}

func (SSH this) Name() string {
	return "ssh"
}
func (SSH this) Description() string {
	return "Secure Shell (SSH)"
}

func (SSH *this) Scan(target string, cred Credential, cmd string, out chan ScanResult) {
	// Add port 22 to the target if we didn't get a port from the user.
	if !strings.Contains(target, ":") {
		target = target + ":22"
	}

	// Declare some variables to hold our SSH connection and any errors
	var err error
	var session *ssh.Session

	// Depending on the authentication type, run the correct connection function
	switch cred.Type {
	case "basic":
		_, session, err = connectByPass(user, target, string(authdata))
	case "sshkey":
		_, session, err = connectByCert(user, target, authdata)
	}

	// Let's assume that we connected successfully and declare the data as such
	result := Result{
		Host:    target,
		Message: "Successfully connected",
		Status:  true,
		Output:  "",
	}

	// If we got an error, let's set the data properly
	if err != nil {
		result.Message = err.Error()
		result.Status = false
	}

	// If we didn't get an error and we have a command to run, let's do it.
	if err == nil && cmd != "" {
		// Execute the command
		result.Output, err = executeCommand(cmd, session)
		if err != nil {
			// If we got an error, let's give the user some output.
			result.Output = "Script Error: " + err.Error()
		}
	}

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result

}
