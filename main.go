package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/emperorcow/go-netscan/scanners"
	"github.com/emperorcow/go-netscan/scanners/ssh"
	"github.com/emperorcow/go-netscan/scanners/winrm"
)

type inputData struct {
	Target string
	Cred   scanners.Credential
}

// A channel to hold our input data.  It will be one target string per line
var inChan chan inputData

// A channel of Result structs to hold our output before written to the file / stdout
var outChan chan scanners.Result

// A channel we'll use to signal when we're out of input so our goroutines can stop
var runDoneChan chan bool
var outDoneChan chan bool

// We'll use this waitgroup to track the total number of routines we have started
// so that everything can stop gracefully
var runDoneWait sync.WaitGroup
var outDoneWait sync.WaitGroup

func main() {
	scannerList := setupScanners()

	// Let's setup our flags and parse them
	optTargets := flag.String("targets", "", "File of targets to connect to (host:port).  Port is optional.")
	optOutFile := flag.String("out", "", "File to write our detailed results to.")
	optProtocol := flag.String("protocol", "", "Protocol to scan with, ask for --help to see all supported.")
	optAuthType := flag.String("authtype", "basic", "Type of authentication to use")
	optAuthFile := flag.String("authfile", "", "A file formatted properly for the authentication type one credential per line")
	// Using the word threads here so it makes sense to end users, but we're really using goroutines
	optThreads := flag.Int("threads", 10, "Number of concurrent connections to attempt.")
	optCmd := flag.String("cmd", "", "Command to run on remote systems. Newlines will be replaced with <br>. <OPTIONAL>")
	optHelp := flag.Bool("help", false, "Get a full listing of every protocol, the supported authentication, and input file examples")
	flag.Parse()

	// If we got the help flag, ignore everything else and just print out everything we've got
	if *optHelp {
		fmt.Print("Usage: \n")
		flag.PrintDefaults()
		printScannerHelpData(scannerList)
		return
	}

	// If we didn't get any targets, print an error.
	if *optTargets == "" {
		fmt.Fprint(os.Stderr, "ERROR: Target file was not defined.\n")
		flag.PrintDefaults()
		return
	}

	// If we didn't get an output file, error out.
	if *optOutFile == "" {
		fmt.Fprint(os.Stderr, "ERROR: Output file was not defined.\n")
	}

	// If we can't create the output file, error out
	outFile, err := os.Create(*optOutFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to create output file: %s\n", err.Error())
	}
	defer outFile.Close()

	// If we didn't get a protocol, print an error.
	if *optProtocol == "" {
		fmt.Fprint(os.Stderr, "ERROR: Protocol was not defined.\n")
		flag.PrintDefaults()
		return
	}

	// Check and make sure we support the protocol
	if _, ok := scannerList[*optProtocol]; !ok {
		fmt.Fprintf(os.Stderr, "ERROR: %s is not a supported protocol.", *optProtocol)
	}

	// If we didn't get a auth file, print an error.
	if *optAuthFile == "" {
		fmt.Fprint(os.Stderr, "ERROR: Authentication file was not defined.\n")
		flag.PrintDefaults()
		return
	}

	// Check to make sure we support this authentication type
	if !checkAuthType(scannerList[*optProtocol], *optAuthType) {
		fmt.Fprintf(os.Stderr, "ERROR: Authentication type '%s' is not supported.\n", *optAuthType)
		flag.PrintDefaults()
		return
	}

	// Parse all of our credentials into memory for our use from the input file
	credentials, err := parseCredentials(*optAuthFile, *optAuthType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not parse credential file: %s", err)
		flag.PrintDefaults()
		return
	}

	// Setup our input channels, with out and done being async, but limit in to
	// the number of goroutines we're going to use
	inChan = make(chan inputData, *optThreads)
	outChan = make(chan scanners.Result)
	runDoneChan = make(chan bool, *optThreads)
	outDoneChan = make(chan bool, 1)

	// Startup a goroutine that will handle our output (stdout and file)
	go runOutput(outFile)

	// Startup goroutines for the number the user gave us.  Each will connect to hosts
	// and try and run a command if one was provided.
	for i := 0; i < *optThreads; i++ {
		go runScanners(scannerList[*optProtocol], *optCmd)
	}

	// This function loops through all of our input and adds it to the proper
	// channel.  If we can't open the intput file, we should error and die.
	err = runInput(*optTargets, credentials)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to open input file: %s\n", err.Error())
		return
	}

	// Finally, let's signal all of our goroutines (+1 is for output routine) and
	// tell them we're done, then wait for them all to shutdown
	signalDone(*optThreads)
	runDoneWait.Wait()

	// Now let's signal the output thread we're done and to shutdown when it's done
	outDoneChan <- true
	outDoneWait.Wait()
}

// This function signals that we're done by sending data down the runDoneChannel that
// we're using as a signal.  It will send that as many times as we have routines
// because we need to make sure each routine gets it at least once.
func signalDone(routines int) {
	for i := 0; i < routines; i++ {
		runDoneChan <- true
	}
}

// This function loops through an input file and adds each line to a channel
// that will be consumed by the runConnect functions.
func runInput(file string, creds []scanners.Credential) error {
	// Open the file and if there's an error, return it
	inFile, err := os.Open(file)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Setup a scanner to read the file line by line
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		for _, cred := range creds {

			// Get the line from the scanner
			line := scanner.Text()

			// Add it to our channel
			inChan <- inputData{
				Target: line,
				Cred:   cred,
			}
		}
	}

	// When we're done with the file, return that we're complete.
	return nil
}

// A function (probably a single goroutine) that handles writing our results to
// both the screen and an output file.  Takes an argument of a file connection
// And then starts a permanent loop that waits for data on the outChan channel
// of result objects.
func runOutput(outFile *os.File) {
	// We're going to increase the waitgroup number so the main routine knows when
	// everything is done.
	outDoneWait.Add(1)

	// Write the header row to our CSV
	outFile.WriteString("'Host','Success','Message','Output'\n")

	// Write a header to the console
	fmt.Printf("%-20s  %-20s  %-20s    %s\n", "Hostname", "Username", "Password", "Result")

	// Create a counter, because we'll want to put in line returns sometimes
	for {
		select {
		// Get some data from our output channel
		case result := <-outChan:
			// We're going to print the IP / target, if we were successful we'll print
			// it in green, if not we'll print it in red.  Full details will be in the
			// output file, but it's nice to provide quick feedback.
			if result.Status {
				fmt.Printf("%-20.20s  %-20.20s  %-20.20s    \033[32;1mSuccess\033[0m\n", result.Host, result.Auth.Account, result.Auth.AuthData)
			} else {
				fmt.Printf("%-20.20s  %-20.20s  %-20.20s    \033[31mFailed\033[0m\n", result.Host, result.Auth.Account, result.Auth.AuthData)
			}

			// Finally, let's write the string to our output file.
			outFile.WriteString(fmt.Sprintf("'%s','%s','%s','%t','%s','%s'\n", result.Host, result.Auth.Account, result.Auth.AuthData, result.Status, result.Message, replaceNewLines(result.Output)))

		// We'll use runDoneChan to signal that the program is complete (probably out of input).
		// Once we're done printing all of our output, let's signal that we're done.
		case <-outDoneChan:
			outDoneWait.Done()
			return
		}
	}
}

// Starts a loop that listens for targets on the inChan channel.  When a target
// is in the channel, it pops it off, and connects to the target using
// authentication information passed in as arguments.  Authtype should be either
// "pass" or "key" to signal how we should connect.  It will also run a command
// if one is provided and gather the output.  There are no returns, but when
// complete passes a Result struct down the outChan channel.
//
// To end this loop, any data should be sent down the runDoneChan to signal program
// complete.
func runScanners(scanner scanners.Scanner, exec string) {
	// Let's increase the WaitGroup we have so main knows how many goroutines are
	// running.
	runDoneWait.Add(1)

	for {
		select {
		//In the event we have a target, let's process it.
		case inData := <-inChan:
			scanner.Scan(inData.Target, exec, inData.Cred, outChan)
			// TODO: Add forced timeouts to scans

		// We'll use doneChan to signal that the program is complete (probably out of input).
		// When we get data on this channel as a signal, we'll signal that this routine is done
		// so main knows when they're all complete.  Finally, we'll return
		case <-runDoneChan:
			runDoneWait.Done()
			return
		default:
		}
	}
}

// A function to process through all of the scanners we have and load them into a map
func setupScanners() map[string]scanners.Scanner {
	scanners := make(map[string]scanners.Scanner)

	// If adding a new scanner, you must add it to this array because Go is static and we're
	// not supporting plugins for now because they don't work in Windows
	scanners["ssh"] = ssh.NewScanner()
	scanners["winrm"] = winrm.NewScanner()

	return scanners
}

// A function to process through and print all of the examples for auth types
func printScannerHelpData(scanners map[string]scanners.Scanner) {
	fmt.Print("Supported Protocols and associated Authentication Types: \n")

	// First we loop through every scanner and get every auth type
	for _, scanner := range scanners {
		// Print out our scanner info
		fmt.Printf("  - %s: %s\n", scanner.Name(), scanner.Description())
		for key, example := range scanner.SupportedAuthenticationExample() {
			// Print out the authentication types and example input
			fmt.Printf("         %s\t\t%s\n", key, example)
		}
	}
}

// A function to check out and make sure our authentication type is supported
func checkAuthType(scanner scanners.Scanner, auth string) bool {
	// Check to see if we're in the slice by looping through it, if we find it return true
	for _, key := range scanner.SupportedAuthentication() {
		if key == auth {
			return true
		}
	}
	return false
}

// Handles the parsing of credentials files, which will be  comma separated list of
// credential pairs in the format: USERNAME,PASSWORD.  Password and username may
// differ in specific definition based on the authentication type.
func parseCredentials(filePath, authType string) ([]scanners.Credential, error) {
	// Open our file
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return []scanners.Credential{}, err
	}

	// Build a temp location for our credentials
	var tempList []scanners.Credential

	// Open a buffer for the file and loop through each line
	fileScanner := bufio.NewScanner(fileHandle)
	for fileScanner.Scan() {
		// Split the line based on the first comma and then add it to the cred array
		splitData := strings.SplitN(fileScanner.Text(), ",", 2)

		// Add the data to our credential array
		tempList = append(tempList, scanners.Credential{
			Type:     authType,
			Account:  splitData[0],
			AuthData: splitData[1],
		})
	}
	// If there are any errors, we will just return them from this function
	if err := fileScanner.Err(); err != nil {
		return []scanners.Credential{}, err
	}

	return tempList, nil
}

// This function takes a string and replaces all newlines (windows and linux) with
// a <br>.  This is so that console output from run commands will still be on a
// single line.
func replaceNewLines(input string) string {
	temp := strings.Replace(input, "\r\n", "<br>", -1)
	return strings.Replace(temp, "\n", "<br>", -1)
}
