package common

// Hold infromation on all of our
type Credential struct {
	Type     string // The type of authentication we have
	Account  string // The account info or username
	AuthData string // The password or authentication data
}

// Each type of scanner must implement this interface to be compatible.
type Scanner interface {
	// Name should be the string used to uniqely identify each of the scanners within the system for our code and on the CLI as a parameter for the user.
	Name() string
	// Description is the string that will describe this to users
	Description() string
	// A way to return to the users what types of authentication we support
	SupportedAuthentication() []string
	// Examples of each authentication type should look like
	SupportedAuthenticationExample() map[string]string
	// Actually perform a scan.  Will be run in a go-routine
	Scan(target string, cred Credential, out chan ScanResult)
	// Run a command, query, etc. on remote systems
	Execute(target string, cred Credential, out chan ExecResult)
}

// A struct to hold our results before we output them
type Result struct {
	Host    string     //The string used to connect to the host
	Auth    Credential //What we used to authenticate to the target
	Message string     //The output message received
	Output  string     //The output of the command run, if any
	Status  bool       //Whether we were successful or failed
}
