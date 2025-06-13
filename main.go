package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/bizibabe/wappaGo/cmd"
	"github.com/bizibabe/wappaGo/structure"
	"github.com/bizibabe/wappaGo/technologies"
)

func main() {
	options := structure.Options{}
	options.Screenshot = flag.String("screenshot", "", "path to screenshot if empty no screenshot")
	options.Ports = flag.String("ports", "80,443", "port want to scan separated by comma")
	options.Threads = flag.Int("threads", 5, "Number of threads to start recon in same time")
	options.Report = flag.Bool("report", false, "Generate HTML report")
	options.Porttimeout = flag.Int("port-timeout", 2000, "Timeout during port scanning in ms")
	options.ChromeThreads = flag.Int("chrome-threads", 5, "Number of chromes threads in each main threads total = option.threads*option.chrome-threads (Default 5)")
	options.Resolvers = flag.String("resolvers", "", "Use specifique resolver separated by comma")
	options.AmassInput = flag.Bool("amass-input", false, "Pip directly on Amass (Amass json output) like amass -d domain.tld | wappaGo")
	options.FollowRedirect = flag.Bool("follow-redirect", false, "Follow redirect to detect technologie")
	options.Proxy = flag.String("proxy", "", "Use http proxy")
	target := flag.String("target", "", "Specify target directly as a command-line argument")
	flag.Parse()
	configure(options, *target)
}

func configure(options structure.Options, target string) {
	if *options.Screenshot != "" {
		if _, err := os.Stat(*options.Screenshot); errors.Is(err, os.ErrNotExist) {
			err := os.Mkdir(*options.Screenshot, os.ModePerm)
			if err != nil {
				log.Println(err)
			}
		}
	}

	folder := "technologies_json"
	technologies.EmbedTechnologies(folder)

	var input []string
	if target != "" {
		// Use the specified target if provided
		input = append(input, target)
	} else {
		// Fallback to reading from stdin
		var scanner = bufio.NewScanner(bufio.NewReader(os.Stdin))
		for scanner.Scan() {
			input = append(input, scanner.Text())
		}
	}

	c := cmd.Cmd{}
	c.ResultGlobal = technologies.LoadTechnologiesFiles(folder)
	c.Options = options
	c.Input = input

	results := make(chan structure.Data)
	var resultArray []structure.Data // Array to hold all results

	go func() {
		for result := range results {
			resultArray = append(resultArray, result)
		}
	}()

	c.Start(results)

	// Convert the accumulated results to a JSON array and print
	b, err := json.MarshalIndent(resultArray, "", "  ")
	if err != nil {
		log.Println("Error marshalling results:", err)
		return
	}
	fmt.Println(string(b))
}
