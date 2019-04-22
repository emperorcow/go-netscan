package ssh

import (
	"io/ioutil"
	"strings"

	"github.com/emperorcow/go-netscan/scanners"
	"golang.org/x/crypto/ssh"
)

// This is our scanner and does all the work from the main
type Scanner struct{}

// Returns the name of this scanner
func (this Scanner) Name() string {
	return "ssh"
}

// Returns a description of this scanner
func (this Scanner) Description() string {
	return "Secure Shell (Scanner)"
}

// Returns the types of auth we support in this scanner
func (this Scanner) SupportedAuthentication() []string {
	return []string{"basic", "sshkey"}
}

// Returns some examples on how to configure the auth info
func (this Scanner) SupportedAuthenticationExample() map[string]string {
	return map[string]string{
		"basic":  "USERNAME,PASSWORD",
		"sshkey": "USERNAME,/path/to/key/file.pem",
	}
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this Scanner) Scan(target, cmd string, cred scanners.Credential, outChan chan scanners.Result) {
	// Add port 22 to the target if we didn't get a port from the user.
	if !strings.Contains(target, ":") {
		target = target + ":22"
	}

	var config ssh.ClientConfig
	var err error

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
		config, err = this.prepPassConfig(cred.Account, cred.AuthData)
	case "sshkey":
		config, err = this.prepCertConfig(cred.Account, cred.AuthData)
	}

	// Return if we got an error.
	if err != nil {
		result.Message = err.Error()
		result.Status = false
	}

	_, session, err := this.connect(cred.Account, target, config)

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

// Connects to a host using a SSH configuration struct.  Returns the
// SSH client and session structs and an error if there was one.
func (this Scanner) connect(user, host string, conf ssh.ClientConfig) (*ssh.Client, *ssh.Session, error) {
	// Develop the network connection out
	conn, err := ssh.Dial("tcp", host, &conf)
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

// Executes a command on an SSH session struct, return an error if there is one
func (this Scanner) executeCommand(cmd string, session *ssh.Session) (string, error) {
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
func (this Scanner) prepCertConfig(user, keyPath string) (ssh.ClientConfig, error) {
	// Load the key file  from disk
	keyData, err := ioutil.ReadFile(keyPath)

	// If we couldn't open the key file, error out.
	if err != nil {
		return ssh.ClientConfig{}, err
	}

	//Parse the private key, return if there is an error
	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return ssh.ClientConfig{}, err
	}

	//Build the configuration struct we need
	conf := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}

	// Return our config
	return conf, nil
}

// Connects to a target using SSH with a password in a string.
func (this Scanner) prepPassConfig(user, pass string) (ssh.ClientConfig, error) {
	//Build our config with the password
	conf := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pass)},
	}

	// Return our config
	return conf, nil
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return &Scanner{}
}
