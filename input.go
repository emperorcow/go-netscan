package main

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/emperorcow/go-netscan/inputs"
	"github.com/emperorcow/go-netscan/scanners"
)

// This function loops through an input file and adds each line to our input handler
func parseTargets(file string, in inputs.Handler) error {
	// Open the file and if there's an error, return it
	inFile, err := os.Open(file)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Setup a scanner to read the file line by line
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		// Get the line from the scanner and add it
		in.AddTarget(scanner.Text())
	}

	// When we're done with the file, return that we're complete.
	return nil
}

// Handles the parsing of credentials files, which will be  comma separated list of
// credential pairs in the format: USERNAME,PASSWORD.  Password and username may
// differ in specific definition based on the authentication type.
func parseCredentials(filePath, authType string, in inputs.Handler) error {
	// Open our file
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return err
	}

	// Open a buffer for the file and loop through each line
	fileScanner := bufio.NewScanner(fileHandle)
	for fileScanner.Scan() {
		// Split the line based on the first comma and then add it to the cred array
		splitData := strings.SplitN(fileScanner.Text(), ",", 2)

		// Add the data to our input handler
		in.AddCred(scanners.Credential{
			Type:     authType,
			Account:  splitData[0],
			AuthData: splitData[1],
		})
	}
	// If there are any errors, we will just return them from this function
	if err := fileScanner.Err(); err != nil {
		return err
	}

	return nil
}

// Takes a CIDR string and returns a slice of all hosts
// within that range
func cidrToList(cidr string) ([]string, error) {
	tempAddresses := []string{}

	// We'll use the net library to parse it into a netmask and netaddr
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{}, err
	}

	// Then we'll loop through those and use our incrementer to get each ip
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); cidrToListInc(ip) {
		tempAddresses = append(tempAddresses, ip.String())
	}

	return tempAddresses, nil
}

// An incrementer for the for loop in cidrToList, adds one to each IP
// byte we have.
func cidrToListInc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
