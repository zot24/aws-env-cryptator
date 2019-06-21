package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var (
	awsKeyID            string
	inputSecretsFile    string
	outputSecretsFile   string
	encryptationContext string
)

func main() {
	// compiled expression to validate environment variables strings
	validEnvVar := regexp.MustCompile(`^[A-Z0-9=_]+=.*$`)

	// compiled expression to validate a comment line
	commentedLine := regexp.MustCompile(`^\/\/.*$`)

	flag.StringVar(&inputSecretsFile, "f", ".secrets", "File path to read  secrets from, default: .secrets")
	flag.StringVar(&outputSecretsFile, "o", ".encrypted.secrets", "Output file path to write secrets to, default: .encrypted.secrets")
	flag.StringVar(&encryptationContext, "ec", "", "Encryptation context to be used for authenticated encryption, eg: type=credentials,env=production")
	flag.StringVar(&awsKeyID, "key-id", "", "AWS key ID used for encrypted our secrets")
	flag.Parse()

	if awsKeyID == "" {
		log.Println("Required flag `--key-id` not set, e.g. --key-id b82051cc-2488-4ae4-a4ec-27cfb6f65dc9")
		os.Exit(1)
	}

	// open read secrets file
	fi, err := os.Open(inputSecretsFile)
	check(err)
	defer fi.Close()

	// create output file and writer buffer
	fo, err := os.Create(outputSecretsFile)
	check(err)
	wb := bufio.NewWriter(fo)
	defer wb.Flush()

	// loop through processing file
	scanner := bufio.NewScanner(fi)
	for scanner.Scan() {
		line := scanner.Text()

		// skip empty lines
		if len(line) == 0 {
			continue
		}

		// skip commented line
		if commentedLine.MatchString(line) == true {
			continue
		}

		// skip environment variables that are not valid
		if validEnvVar.MatchString(line) != true {
			log.Println("Error: parsing environment variable, value: " + line)
			continue
		}

		// process encryptation context
		ec := ""
		if encryptationContext != "" {
			ec = " --encryption-context '" + encryptationContext + "'"
		}

		parts := strings.Split(line, "=")
		variable := parts[0]
		secret := parts[1]

        // if there is no secret side = env var empty skip
		if secret == "" {
			continue
        }
        
        // edge case processing a secret that its an URL, more info: 
        // https://github.com/aws/aws-cli/issues/2867
        // https://github.com/aws/aws-cli/issues/1043
		if regexp.MustCompile(`^http.*$`).MatchString(secret) {
			secret = "fileb://<(echo -n '" + secret + "')"
		}

		out := execCmd("aws kms encrypt --key-id " + awsKeyID + " --plaintext " + secret + " --output text --query CiphertextBlob" + ec)
		fmt.Fprint(wb, variable+"="+out.String())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

// execCmd Execute a command on the OS with the passed arguments
func execCmd(c string) *bytes.Buffer {
	var out bytes.Buffer

	cmd := exec.Command("bash", "-c", c)
	cmd.Stdout = &out

	err := cmd.Run()
	check(err)

	return &out
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
