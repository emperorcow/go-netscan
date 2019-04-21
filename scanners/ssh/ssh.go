package ssh

import (
	"io/ioutil"
	"strings"

	"github.com/emperorcow/go-netscan/scanners"
	"golang.org/x/crypto/ssh"
)

type sshScanner struct{}

// Returns the name of this scanner
func (this sshScanner) Name() string {
	return "ssh"
}

// Returns a description of this scanner
func (this sshScanner) Description() string {
	return "Secure Shell (sshScanner)"
}

// Returns the types of auth we support in this scanner
func (this sshScanner) SupportedAuthentication() []string {
	return []string{"basic", "sshkey"}
}

// Returns some examples on how to configure the auth info
func (this sshScanner) SupportedAuthenticationExample() map[string]string {
	return map[string]string{
		"basic":  "USERNAME,PASSWORD",
		"sshkey": "USERNAME,/path/to/key/file.pem",
	}
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this sshScanner) Scan(target string, cred scanners.Credential, cmd string, outChan chan scanners.Result) {
	// Add port 22 to the target if we didn't get a port from the user.
	if !strings.Contains(target, ":") {
		target = target + ":22"
	}

	// Declare some variables to hold our sshScanner connection and any errors
	var err error
	var session *ssh.Session

	// Depending on the authentication type, run the correct connection function
	switch cred.Type {
	case "basic":
		_, session, err = this.connectByPass(cred.Account, target, cred.AuthData)
	case "sshkey":
		_, session, err = this.connectByCert(cred.Account, target, cred.AuthData)
	}

	// Let's assume that we connected successfully and declare the data as such
	result := scanners.Result{
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
		result.Output, err = this.executeCommand(cmd, session)
		if err != nil {
			// If we got an error, let's give the user some output.
			result.Output = "Script Error: " + err.Error()
		}
	}

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result

}

// Executes a command on an SSH session struct, return an error if there is one
func (this sshScanner) executeCommand(cmd string, session *ssh.Session) (string, error) {
	//Runs CombinedOutput, which takes cmd and returns stderr and stdout of the command
	out, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", err
	}

	// Convert our output to a string
	tmpOut := string(out)
	tmpOut = strings.Replace(tmpOut, "\n", "<br>", -1)

	// Return a string version of our result
	return tmpOut, nil
}

// Connects to a target via SSH using a certificate
func (this sshScanner) connectByCert(user, host, keyPath string) (*ssh.Client, *ssh.Session, error) {
	// Load the key file  from disk
	keyData, err := ioutil.ReadFile(keyPath)

	// If we couldn't open the key file, error out.
	if err != nil {
		return nil, nil, err
	}

	//Parse the private key, return if there is an error
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, nil, err
	}

	//Build the configuration struct we need
	conf := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}

	// Connect and return the result
	return this.connect(user, host, conf)
}

// Connects to a target using SSH with a password in a string.
func (this sshScanner) connectByPass(user, host, pass string) (*ssh.Client, *ssh.Session, error) {
	//Build our config with the password
	conf := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
	}

	// Connect and return the result
	return this.connect(user, host, conf)
}

// Connects to a host using a SSH configuration struct.  Returns the
// SSH client and session structs and an error if there was one.
func (this sshScanner) connect(user, host string, conf *ssh.ClientConfig) (*ssh.Client, *ssh.Session, error) {
	// Develop the network connection out
	conn, err := ssh.Dial("tcp", host, conf)
	if err != nil {
		return nil, nil, err
	}

	// Actually perform our connection
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return conn, session, nil
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return sshScanner{}
}
