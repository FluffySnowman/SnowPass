package cmd

import (
	"fmt"

	"github.com/fatih/color"
)

func DisplayHelp() {
	color.Yellow("\n===================== Usage =====================\n")
	fmt.Printf("%v\n", color.CyanString("[CREATE]"))
	fmt.Printf("Creates a Keystore to Store Data in\n")
	fmt.Printf("Usage:\t\tsnowpass create [%v]\n", color.GreenString("keystore"))
	fmt.Printf("Example:\tsnowpass create %v\n\n", color.GreenString("work"))

	fmt.Printf("%v\n", color.YellowString("[ADD]"))
	fmt.Printf("Adds an entry to a specified Keystore\n")
	fmt.Printf("Usage:\t\tsnowpass add %v to %v\n", color.GreenString("[identifier]"), color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass add %v to %v\n\n", color.GreenString("github_token"), color.CyanString("work"))

	fmt.Printf("%v\n", color.MagentaString("[LIST]"))
	fmt.Printf("Lists all entries in a specified Keystore or all Keystores\n")
	fmt.Printf("Usage:\t\tsnowpass list %v\n", color.GreenString("[keystoreName|all]"))
	fmt.Printf("Example:\tsnowpass list %v\n", color.GreenString("work"))
	fmt.Printf("Example:\tsnowpass list %v\n\n", color.GreenString("all"))

	fmt.Printf("%v\n", color.BlueString("[GET]"))
	fmt.Printf("Retrieves the data for an identifier from a specified Keystore\n")
	fmt.Printf("Usage:\t\tsnowpass get %v from %v\n", color.GreenString("[identifier]"), color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass get %v from %v\n\n", color.GreenString("github_token"), color.CyanString("work"))

	fmt.Printf("%v\n", color.CyanString("[COPY]"))
	fmt.Printf("Copies specified data to the clipboard\n")
	fmt.Printf("Usage:\t\tsnowpass copy %v from %v\n", color.GreenString("[identifier]"), color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass copy %v from %v\n\n", color.GreenString("github_token"), color.CyanString("work"))

	fmt.Printf("%v\n", color.GreenString("[EDIT]"))
	fmt.Printf("Edit or delet the data for an existing identifier in a specified Keystore\n")
	fmt.Printf("Usage:\t\tsnowpass edit %v in %v\n", color.GreenString("[identifier]"), color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass edit %v in %v\n\n", color.GreenString("github_token"), color.CyanString("work"))

	fmt.Printf("%v\n", color.YellowString("[CHANGE-PASSWORD]"))
	fmt.Printf("Change the password for a specified Keystore\n")
	fmt.Printf("Usage:\t\tsnowpass change-password %v\n", color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass change-password %v\n\n", color.CyanString("work"))

	fmt.Printf("%v\n", color.RedString("[DELETE]"))
	fmt.Printf("Deletes an identifier and its data from a specified Keystore\n")
	fmt.Printf("Usage:\t\tsnowpass delete %v from %v\n", color.GreenString("[identifier]"), color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass delete %v from %v\n\n", color.GreenString("github_token"), color.CyanString("work"))

	fmt.Printf("%v\n", color.RedString("[DELETE-KEYSTORE]"))
	color.Red("DELETES THE KEYSTORE ENTIRELY\n")
	fmt.Printf("Usage:\t\tsnowpass delete-keystore %v\n", color.CyanString("[keystore]"))
	fmt.Printf("Example:\tsnowpass delete-keystore %v\n\n", color.CyanString("work"))

	color.Yellow("\n=================== END Usage ===================\n")

}
