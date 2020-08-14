package wmi

import (
	"math/rand"
	"strings"
	"time"

	"github.com/C-Sto/goWMIExec/pkg/wmiexec"
	"github.com/emperorcow/go-netscan/scanners"
)

// This is our scanner and does all the work from the main
type Scanner struct{}

// Returns the name of this scanner
func (this Scanner) Name() string {
	return "wmi"
}

// Returns a description of this scanner
func (this Scanner) Description() string {
	return "Windows Management Instrumentation (WMI)"
}

// Returns the types of auth we support in this scanner
func (this Scanner) SupportedAuthentication() []string {
	return []string{"basic"}
}

// Returns some examples on how to configure the auth info
func (this Scanner) SupportedAuthenticationExample() map[string]string {
	return map[string]string{
		"basic": "USERNAME,PASSWORD,HASH",
	}
}

// Runs the actual scan, takes an input of our target, the creds we need to use for this one,
// a command to run if we have one, and our out channel for results
func (this Scanner) Scan(target, cmd string, cred scanners.Credential, outChan chan scanners.Result) {

	var err error

	// Add port 135 to the target if we didn't get a port from the user.
	if !strings.Contains(target, ":") {
		target = target + ":135"
	}

	var userdomain, username, userpassword, userhash string

	// Check and see if we have a logon domain in our user (DOMAIN\USER)
	if strings.Contains(cred.Account, "\\") {
		logonInfo := strings.Split(cred.Account, "\\")
		userdomain = logonInfo[0]
		username = logonInfo[1]
	} else {
		username = cred.Account
	}

	// Extract the hash and password from the credentials
	if strings.Contains(cred.AuthData, ",") {
		credz := strings.Split(cred.AuthData, ",")
		userpassword = credz[0]
		userhash = credz[1]
	}

	// Let's assume that we connected successfully and declare the data as such, we can edit it later if we failed
	result := scanners.Result{
		Host:    target,
		Auth:    cred,
		Message: "Successfully connected",
		Status:  true,
		Output:  "",
	}

	cfg, err := wmiexec.NewExecConfig(username, userpassword, userhash, userdomain, target, RandHostName(), true, nil, nil)
	if err != nil {
		result.Output = "Config Error: " + err.Error()
	}
	cfgIn := &cfg

	execer := wmiexec.NewExecer(cfgIn)
	err = execer.Connect()
	if err != nil {
		result.Output = "Connect Error: " + err.Error()
	}

	err = execer.Auth()
	if err != nil {
		result.Output = "Authentication Error: " + err.Error()
	}

	if cmd != "" {
		err = execer.RPCConnect()
		if err != nil {
			result.Output = "RPC Error: " + err.Error()
		}
		err = execer.Exec(cmd)
		if err != nil {
			result.Output = "Execution Error: " + err.Error()
		}
	}

	result.Output = "Execution Success"

	// Finally, let's pass our result to the proper channel to write out to the user
	outChan <- result
}

// Creates a new scanner for us to add to the main loop
func NewScanner() scanners.Scanner {
	return &Scanner{}
}

func RandHostName() string {
	rand.Seed(time.Now().UnixNano())
	digits := "0123456789"
	specials := "-"
	all := "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		digits + specials
	length := 16
	buf := make([]byte, length)
	buf[0] = digits[rand.Intn(len(digits))]
	buf[1] = specials[rand.Intn(len(specials))]
	for i := 2; i < length; i++ {
		buf[i] = all[rand.Intn(len(all))]
	}
	rand.Shuffle(len(buf), func(i, j int) {
		buf[i], buf[j] = buf[j], buf[i]
	})
	return string(buf) // E.g. "3i[g0|)z"
}
