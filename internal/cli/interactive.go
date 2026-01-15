// Package cli provides the interactive command-line interface for cloak.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/vsamidurai/cloak/internal/cloak"
)

// commands available in interactive mode.
var commands = []prompt.Suggest{
	{Text: "encrypt", Description: "Encrypt a folder into a .cloak file"},
	{Text: "decrypt", Description: "Decrypt a .cloak file back to folder"},
	{Text: "help", Description: "Show available commands"},
	{Text: "exit", Description: "Exit interactive mode"},
}

// completer provides autocomplete suggestions.
func completer(d prompt.Document) []prompt.Suggest {
	text := d.TextBeforeCursor()
	words := strings.Fields(text)

	// No input yet - suggest commands
	if len(words) == 0 {
		return prompt.FilterHasPrefix(commands, d.GetWordBeforeCursor(), true)
	}

	// First word being typed - suggest commands
	if len(words) == 1 && !strings.HasSuffix(text, " ") {
		return prompt.FilterHasPrefix(commands, d.GetWordBeforeCursor(), true)
	}

	// Command typed, suggest file paths
	cmd := words[0]
	var prefix string
	if len(words) > 1 {
		prefix = words[len(words)-1]
		if strings.HasSuffix(text, " ") {
			prefix = ""
		}
	}

	switch cmd {
	case "encrypt":
		return filterDirectories(prefix)
	case "decrypt":
		return filterCloakFiles(prefix)
	}

	return nil
}

// filterDirectories returns directory suggestions for encryption.
func filterDirectories(prefix string) []prompt.Suggest {
	return getPathSuggestions(prefix, func(entry os.DirEntry, path string) bool {
		return entry.IsDir()
	}, "Directory")
}

// filterCloakFiles returns .cloak file suggestions for decryption.
func filterCloakFiles(prefix string) []prompt.Suggest {
	return getPathSuggestions(prefix, func(entry os.DirEntry, path string) bool {
		return !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cloak")
	}, "Encrypted file")
}

// getPathSuggestions returns file path suggestions filtered by the given predicate.
func getPathSuggestions(prefix string, filter func(os.DirEntry, string) bool, desc string) []prompt.Suggest {
	var suggestions []prompt.Suggest

	// Determine the directory to search
	searchDir := "."
	searchPrefix := prefix

	if prefix != "" {
		dir := filepath.Dir(prefix)
		if dir != "." {
			searchDir = dir
		}
		searchPrefix = filepath.Base(prefix)
		// If prefix ends with separator, search inside that directory
		if strings.HasSuffix(prefix, string(filepath.Separator)) {
			searchDir = prefix
			searchPrefix = ""
		}
	}

	entries, err := os.ReadDir(searchDir)
	if err != nil {
		return suggestions
	}

	for _, entry := range entries {
		name := entry.Name()
		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			continue
		}

		var fullPath string
		if searchDir == "." {
			fullPath = name
		} else {
			fullPath = filepath.Join(searchDir, name)
		}

		// Add directories for navigation (always useful)
		if entry.IsDir() {
			dirPath := fullPath + string(filepath.Separator)
			if searchPrefix == "" || strings.HasPrefix(strings.ToLower(name), strings.ToLower(searchPrefix)) {
				suggestions = append(suggestions, prompt.Suggest{
					Text:        dirPath,
					Description: "Directory",
				})
			}
		}

		// Add matching files/dirs based on filter
		if filter(entry, fullPath) && !entry.IsDir() {
			if searchPrefix == "" || strings.HasPrefix(strings.ToLower(name), strings.ToLower(searchPrefix)) {
				suggestions = append(suggestions, prompt.Suggest{
					Text:        fullPath,
					Description: desc,
				})
			}
		}
	}

	return suggestions
}

// executor handles command execution.
func executor(input string) {
	input = strings.TrimSpace(input)
	if input == "" {
		return
	}

	words := strings.Fields(input)
	cmd := words[0]

	switch cmd {
	case "encrypt":
		if len(words) < 2 {
			fmt.Println("Usage: encrypt <folder_path>")
			fmt.Println("Example: encrypt ./my_folder")
			return
		}
		path := strings.TrimSuffix(words[1], string(filepath.Separator))
		if err := cloak.Encrypt(path); err != nil {
			fmt.Printf("Error: %v\n", err)
		}

	case "decrypt":
		if len(words) < 2 {
			fmt.Println("Usage: decrypt <file_path>")
			fmt.Println("Example: decrypt ./my_folder.cloak")
			return
		}
		if err := cloak.Decrypt(words[1]); err != nil {
			fmt.Printf("Error: %v\n", err)
		}

	case "help":
		printInteractiveHelp()

	case "exit", "quit":
		fmt.Println("Goodbye!")
		os.Exit(0)

	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		fmt.Println("Type 'help' for available commands")
	}
}

// printInteractiveHelp prints help for interactive mode.
func printInteractiveHelp() {
	fmt.Println()
	fmt.Println("Available commands:")
	fmt.Println("  encrypt <folder>  Encrypt a folder into a .cloak file")
	fmt.Println("  decrypt <file>    Decrypt a .cloak file back to folder")
	fmt.Println("  help              Show this help message")
	fmt.Println("  exit              Exit interactive mode")
	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  - Press Tab for autocomplete suggestions")
	fmt.Println("  - Use arrow keys to navigate suggestions")
	fmt.Println("  - Press Ctrl+D or type 'exit' to quit")
	fmt.Println()
}

// RunInteractive starts the interactive prompt.
func RunInteractive() {
	fmt.Println("Cloak Interactive Mode")
	fmt.Println("Type 'help' for commands, Tab for autocomplete, Ctrl+D to exit")
	fmt.Println()

	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix("cloak> "),
		prompt.OptionTitle("Cloak"),
		prompt.OptionPrefixTextColor(prompt.Cyan),
		prompt.OptionSelectedSuggestionBGColor(prompt.DarkGray),
		prompt.OptionSuggestionBGColor(prompt.DarkGray),
		prompt.OptionDescriptionBGColor(prompt.DarkGray),
		prompt.OptionSelectedDescriptionBGColor(prompt.Cyan),
		prompt.OptionMaxSuggestion(10),
	)
	p.Run()
}
