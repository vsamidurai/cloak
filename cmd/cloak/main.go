// Cloak is a secure directory encryption CLI tool.
package main

import (
	"fmt"
	"os"

	"github.com/vsamidurai/cloak/internal/cloak"
)

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	path := os.Args[2]

	var err error
	switch command {
	case "encrypt":
		err = cloak.Encrypt(path)
	case "decrypt":
		err = cloak.Decrypt(path)
	default:
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Cloak - Secure Directory Encryption Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cloak encrypt <folder_path>  Encrypt a folder into a single encrypted file")
	fmt.Println("  cloak decrypt <file_path>    Decrypt a .cloak file back to original folder")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cloak encrypt ./my_folder    Creates my_folder.cloak")
	fmt.Println("  cloak decrypt ./my_folder.cloak")
}
