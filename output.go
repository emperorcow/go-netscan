package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/emperorcow/go-netscan/scanners"
)

// This function takes a string and replaces all newlines (windows and linux) with
// a <br>.  This is so that console output from run commands will still be on a
// single line.
func replaceNewLines(input string) string {
	temp := strings.Replace(input, "\r\n", "<br>", -1)
	return strings.Replace(temp, "\n", "<br>", -1)
}

// A function (probably a single goroutine) that handles writing our results to
// both the screen and an output file.  Takes an argument of a file connection
// And then starts a permanent loop that waits for data on the outChan channel
// of result objects.
func runOutput(outFile *os.File, outChan chan scanners.Result) {
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
