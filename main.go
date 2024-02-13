package main

import (
	// "bufio"
	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/rand"
	// "encoding/hex"
	// "encoding/json"
	"fmt"
	// "io"
	// "io/ioutil"
	"os"
	"path/filepath"

	// "strings"

	// "time"

	// "github.com/fatih/color"
	// "golang.design/x/clipboard"
	// "github.com/atotto/clipboard"
	// "golang.org/x/crypto/scrypt"
	// "golang.org/x/term"

	"github.com/fluffysnowman/snowpass/cmd"
	// "github.com/fluffysnowman/snowpass/models"
	"github.com/fluffysnowman/snowpass/states"
	"github.com/fluffysnowman/snowpass/utils"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "help" {
		cmd.DisplayHelp()
		return
	}

	states.GlobalDataDirectory = utils.GetFullDataDir()
	var dataDir = states.GlobalDataDirectory

	mode := os.Args[1]
	var identifier, keystoreName, keystorePath string

	switch mode {
	case "create":
		if len(os.Args) != 3 {
			fmt.Println("Usage for create: snowpass create [keystore]")
			return
		}
		keystoreName = os.Args[2]
	case "add", "get", "copy":
		if len(os.Args) < 5 {
			fmt.Println("Usage for add: snowpass add [identifier] to [keystore]")
			fmt.Println("Usage for get: snowpass get [identifier] from [keystore]")
			return
		}
		identifier = os.Args[2]
		if (mode == "add" && os.Args[3] != "to") || (mode == "get" && os.Args[3] != "from") {
			fmt.Printf("Invalid syntax for '%s'. Use `help` for more info.\n", mode)
			return
		}
		keystoreName = os.Args[4]
	case "edit":
		identifier = os.Args[2]
		keystoreName = os.Args[4]
		keystorePath = filepath.Join(dataDir, keystoreName+".json")
		cmd.EditInKeystore(keystorePath, identifier)
		return
	case "delete":
		identifier = os.Args[2]
		keystoreName = os.Args[4]
		keystorePath = filepath.Join(dataDir, keystoreName+".json")
		cmd.DeleteFromKeystore(keystorePath, identifier, keystoreName)
		return
	case "delete-keystore":
		keystoreName = os.Args[2]
		keystorePath = filepath.Join(dataDir, keystoreName+".json")
		cmd.DeleteKeystore(keystorePath)
		return
	case "change-password":
		keystoreName = os.Args[2]
		keystorePath = filepath.Join(dataDir, keystoreName+".json")
		cmd.ChangeMasterPassword(keystorePath)
		return
	case "list":
		cmd.ListAllKeystores(dataDir)
		return
	default:
		fmt.Println("Invalid mode. Use 'create', 'add', 'get', or 'list'.")
		return
	}

	keystorePath = filepath.Join(dataDir, keystoreName+".json")

	switch mode {
	case "create":
		cmd.CreateKeystore(keystorePath, keystoreName)
	case "add":
		cmd.AddToKeystore(keystorePath, identifier, keystoreName)
	case "get":
		cmd.GetFromKeystore(keystorePath, identifier)
	case "copy":
		cmd.CopyToClipboard(keystorePath, identifier)

		// idk why this isn't working
		// do not uncomment since everything breaks
		// for some reason

		/* case "list":
		if keystoreName == "all" {
			listAllKeystores()
		} else {
			listKeystore(keystoreName)
		}*/
	}
}
