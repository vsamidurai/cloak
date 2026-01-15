// Cloak is a secure directory encryption CLI tool.
package main

import (
	"fmt"
	"os"

	"github.com/vsamidurai/cloak/internal/cloak"
	"github.com/vsamidurai/cloak/internal/cli"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "-i", "--interactive":
		cli.RunInteractive()
		return
	case "-h", "--help", "help":
		printUsage()
		return
	case "encrypt":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: encrypt requires a folder path")
			fmt.Fprintln(os.Stderr, "Usage: cloak encrypt <folder_path>")
			os.Exit(1)
		}
		if err := cloak.Encrypt(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "decrypt":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Error: decrypt requires a file path")
			fmt.Fprintln(os.Stderr, "Usage: cloak decrypt <file_path>")
			os.Exit(1)
		}
		if err := cloak.Decrypt(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Cloak - Secure Directory Encryption Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cloak encrypt <folder_path>  Encrypt a folder into a .cloak file")
	fmt.Println("  cloak decrypt <file_path>    Decrypt a .cloak file back to folder")
	fmt.Println("  cloak -i, --interactive      Start interactive mode with autocomplete")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -h, --help                   Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cloak encrypt ./my_folder    Creates my_folder.cloak")
	fmt.Println("  cloak decrypt ./my_folder.cloak")
	fmt.Println("  cloak -i                     Enter interactive mode")
}
