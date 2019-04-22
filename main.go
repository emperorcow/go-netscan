package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/emperorcow/go-netscan/inputs"
	"github.com/emperorcow/go-netscan/inputs/wide"
	"github.com/emperorcow/go-netscan/scanners"
	"github.com/emperorcow/go-netscan/scanners/ssh"
	"github.com/emperorcow/go-netscan/scanners/winrm"
)

// A channel we'll use to signal when we're out of input so our goroutines can stop
var runDoneChan chan bool
var outDoneChan chan bool

// We'll use this waitgroup to track the total number of routines we have started
// so that everything can stop gracefully
var runDoneWait sync.WaitGroup
var outDoneWait sync.WaitGroup

func main() {
	scannerList := setupScanners()
	inputList := setupInputs()

	// Let's setup our flags and parse them
	optTargets := flag.String("tF", "", "File of targets to connect to (host:port).  Port is optional.")
	optTargetProcess := flag.String("tP", "wide", "The targeting process to be used (wide, deep, random). DEFAULT: wide")
	optOutFile := flag.String("o", "", "File to write our detailed results to.")
	optProtocol := flag.String("p", "", "Protocol to scan with, ask for --help to see all supported.")
	optAuthType := flag.String("aT", "basic", "Type of authentication to use, check help for supported types.  DEFAULT: basic")
	optAuthFile := flag.String("aF", "", "A file formatted properly for the authentication type one credential per line")
	optCmd := flag.String("c", "", "Command to run on remote systems. Newlines will be replaced with <br>. <OPTIONAL>")
	// Using the word threads here so it makes sense to end users, but we're really using goroutines
	optThreads := flag.Int("threads", 10, "Number of concurrent connections to attempt. DEFAULT: 10")
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

	// Check to make sure the target process we have is real
	if !checkInputHandler(inputList, *optTargetProcess) {
		fmt.Fprintf(os.Stderr, "ERROR: The input processor '%s' does not exist.\n", *optTargetProcess)
		flag.PrintDefaults()
		return
	}
	handlerObj := inputList[*optTargetProcess]

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
	scanObj := scannerList[*optProtocol]

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
	err = parseCredentials(*optAuthFile, *optAuthType, handlerObj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not parse credential file: %s", err)
		flag.PrintDefaults()
		return
	}

	// This function loops through all of our input and adds it to the handler.
	// If we can't open the intput file, we should error and die.
	err = parseTargets(*optTargets, handlerObj)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to open target file: %s\n", err.Error())
		return
	}

	// Setup our input channels, with out and done being async, but limit in to
	// the number of goroutines we're going to use
	outChan := make(chan scanners.Result)
	runDoneChan = make(chan bool, *optThreads)
	outDoneChan = make(chan bool, 1)

	// Startup a goroutine that will handle our output (stdout and file)
	go runOutput(outFile, outChan)

	// Startup goroutines for the number the user gave us.  Each will connect to hosts
	// and try and run a command if one was provided.
	for i := 0; i < *optThreads; i++ {
		go runScanners(scanObj, *optCmd, outChan, handlerObj.Chan())
	}

	// Startup sending our inputs to the scanners
	handlerObj.Run()

	// Finally, let's signal all of our goroutines and tell them we're done,
	// then wait for them all to shutdown
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

// Starts a loop that listens for targets on the in channel.  When a target
// is in the channel, it pops it off, and connects to the target using
// authentication information passed in as arguments.  Authtype should be either
// "pass" or "key" to signal how we should connect.  It will also run a command
// if one is provided and gather the output.  There are no returns, but when
// complete passes a Result struct down the out channel.
//
// To end this loop, any data should be sent down the runDoneChan to signal program
// complete.
func runScanners(scanner scanners.Scanner, exec string, out chan scanners.Result, in chan inputs.Data) {
	// Let's increase the WaitGroup we have so main knows how many goroutines are
	// running.
	runDoneWait.Add(1)

	for {
		select {
		//In the event we have a target, let's process it.
		case inData := <-in:
			scanner.Scan(inData.Target, exec, inData.Cred, out)
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
	scanners["vnc"] = winrm.NewScanner()

	return scanners
}

// A function to setup all of our input handlers
func setupInputs() map[string]inputs.Handler {
	handlers := make(map[string]inputs.Handler)

	// If we add any new handlers, they go here
	handlers["wide"] = wide.NewHandler()

	return handlers
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

// A function to check and make sure our input handler exists
func checkInputHandler(list map[string]inputs.Handler, key string) bool {
	if _, ok := list[key]; ok {
		return true
	} else {
		return false
	}
}
