package cmd

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"

	"github.com/fluffysnowman/snowpass/models"
	"github.com/fluffysnowman/snowpass/states"
	"github.com/fluffysnowman/snowpass/utils"
)

type Keystore models.Keystore

var dataDir = states.GlobalDataDirectory

var currentKeystoreID string

func setCurrentKeystoreID(keystoreID string) {
	currentKeystoreID = keystoreID
}

func getCurrentKeystoreID() string {
	return currentKeystoreID
}

var bypassSessionCheck bool

func setBypassSessionCheck(bypass bool) {
	bypassSessionCheck = bypass
}

func promptForPassword(verify bool, keystoreID string) (string, error) {
	setCurrentKeystoreID(keystoreID)

	if !bypassSessionCheck {
		password, err := getKeystorePassword(keystoreID)
		if err == nil {
			return password, nil
		}
	}

	fmt.Print("Enter Master Password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	password := string(bytePassword)
	fmt.Println()

	if verify {
		fmt.Print("Verify password: ")
		byteVerifyPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		verifyPassword := string(byteVerifyPassword)
		fmt.Println()

		if password != verifyPassword {
			return "", fmt.Errorf("passwords do not match")
		}
	}

	if !bypassSessionCheck {
		storeKeystorePassword(keystoreID, strings.TrimSpace(password))
	}

	return strings.TrimSpace(password), nil
}

func promptForData() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter data: ")
	data, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	data = strings.TrimSpace(data)

	fmt.Print("Verify data: ")
	verifyData, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	verifyData = strings.TrimSpace(verifyData)

	if data != verifyData {
		return "", fmt.Errorf("data entries do not match")
	}

	return data, nil
}

func CreateKeystore(keystorePath string, keystoreName string) {
	if _, err := os.Stat(keystorePath); err == nil {
		fmt.Println("Keystore already exists.")
		return
	}

	keystoreID := filepath.Base(keystorePath)
	setBypassSessionCheck(true) // Force a new password prompt
	password, err := promptForPassword(true, keystoreID)
	setBypassSessionCheck(false)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	ks := Keystore{Passwords: make(map[string]string)}
	saveKeystore(keystorePath, &ks, password)
	createEmptyIndex(keystoreName)
}

func AddToKeystore(keystorePath, identifier, keystoreName string) {
	keystoreID := filepath.Base(keystorePath)
	setCurrentKeystoreID(keystoreID)

	password, err := promptForPassword(false, keystoreID)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	data, err := promptForData()
	if err != nil {
		fmt.Println("Failed to read data:", err)
		return
	}

	ks, err := loadKeystore(keystorePath, password)
	if err != nil {
		fmt.Println("Failed to load keystore:", err)
		return
	}

	encryptedData, err := encrypt(data, password)
	if err != nil {
		fmt.Println("Failed to encrypt data:", err)
		return
	}

	ks.Passwords[identifier] = encryptedData
	saveKeystore(keystorePath, ks, password)
	updateKeystoreIndex(keystoreName, identifier, true)
}

func GetFromKeystore(keystorePath, identifier string) {
	keystoreID := filepath.Base(keystorePath)
	setCurrentKeystoreID(keystoreID)

	password, err := promptForPassword(false, keystoreID)
	if err != nil {
		fmt.Println("Failed to read password:", err)
		return
	}

	ks, err := loadKeystore(keystorePath, password)
	if err != nil {
		fmt.Println("Failed to load keystore:", err)
		return
	}

	encryptedData, exists := ks.Passwords[identifier]
	if !exists {
		fmt.Println("Identifier not found.")
		return
	}

	data, err := decrypt(encryptedData, password)
	if err != nil {
		fmt.Println("Failed to decrypt data:", err)
		return
	}

	fmt.Println(data)
	storeKeystorePassword(keystoreID, password)
}

func encrypt(data, password string) (string, error) {
	key, salt, err := deriveKey(password, nil)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := aesGCM.Seal(nonce, nonce, []byte(data), nil)
	return fmt.Sprintf("%x:%x", salt, encrypted), nil
}

func decrypt(encryptedData, password string) (string, error) {
	parts := strings.SplitN(encryptedData, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid encrypted data format")
	}

	salt, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	encrypted, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key, _, err := deriveKey(password, salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encrypted) < nonceSize {
		return "", fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	decrypted, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func deriveKey(password string, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 8)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}

	key, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}

	return key, salt, nil
}

func saveKeystore(keystorePath string, ks *Keystore, password string) {
	data, err := json.Marshal(ks)
	if err != nil {
		fmt.Println("Failed to marshal keystore:", err)
		return
	}

	encryptedData, err := encrypt(string(data), password)
	if err != nil {
		fmt.Println("Failed to encrypt keystore:", err)
		return
	}

	if err := ioutil.WriteFile(keystorePath, []byte(encryptedData), 0644); err != nil {
		fmt.Println("Failed to save keystore:", err)
	}
}

func createEmptyIndex(keystoreName string) {
	indexPath := getIndexFilePath(keystoreName)
	ioutil.WriteFile(indexPath, []byte("[]"), 0644)
}

func updateKeystoreIndex(keystoreName, identifier string, add bool) {
	indexPath := getIndexFilePath(keystoreName)
	data, err := ioutil.ReadFile(indexPath)
	if err != nil {
		fmt.Println("Error reading index file:", err)
		return
	}

	var identifiers []string
	err = json.Unmarshal(data, &identifiers)
	if err != nil {
		fmt.Println("Error parsing index file:", err)
		return
	}

	if add {
		found := false
		for _, id := range identifiers {
			if id == identifier {
				found = true
				break
			}
		}
		if !found {
			identifiers = append(identifiers, identifier)
		}
	} else {
		for i, id := range identifiers {
			if id == identifier {
				identifiers = append(identifiers[:i], identifiers[i+1:]...)
				break
			}
		}
	}

	updatedData, err := json.Marshal(identifiers)
	if err != nil {
		fmt.Println("Error marshaling updated index:", err)
		return
	}

	ioutil.WriteFile(indexPath, updatedData, 0644)
}

func getIndexFilePath(keystoreName string) string {
	keystoreIndexJsonFileDirectoryPathShit := utils.GetFullDataDir()
	return filepath.Join(keystoreIndexJsonFileDirectoryPathShit, keystoreName+"_index.json")
}

func loadKeystore(keystorePath, password string) (*Keystore, error) {
	encryptedData, err := ioutil.ReadFile(keystorePath)
	if err != nil {
		return nil, err
	}

	data, err := decrypt(string(encryptedData), password)
	if err != nil {
		return nil, err
	}

	var ks Keystore
	if err := json.Unmarshal([]byte(data), &ks); err != nil {
		return nil, err
	}

	return &ks, nil
}

func ListAllKeystores(listDataDir string) {
	fmt.Println("SnowPass")
	files, err := ioutil.ReadDir(listDataDir)
	if err != nil {
		fmt.Println("Failed to read user data directory:", err)
		return
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" && !strings.Contains(file.Name(), "_index") {
			keystoreName := strings.TrimSuffix(file.Name(), ".json")
			fmt.Printf("└── ")
			color.Blue(keystoreName)
			listKeystore(keystoreName)
		}
	}

	fmt.Println("\n\n========== DEBUG ============")
	fmt.Println("data directory location (for debugging) (may not work on windows)")
	color.Cyan("Quote: Computers are like air conditioners. they become useless when you open windows")
	fmt.Println(listDataDir)
	fmt.Println("======== END DEBUG ==========")
}

func listKeystore(keystoreName string) {
	indexPath := getIndexFilePath(keystoreName)
	data, err := ioutil.ReadFile(indexPath)
	if err != nil {
		fmt.Printf("Failed to load index for keystore: %s\n", keystoreName)
		return
	}

	var identifiers []string
	if err := json.Unmarshal(data, &identifiers); err != nil {
		fmt.Printf("Failed to parse index for keystore: %s\n", keystoreName)
		return
	}

	for _, identifier := range identifiers {
		fmt.Printf("    ├── %s\n", identifier)
	}
}

func EditInKeystore(keystorePath, identifier string) {
	keystoreID := filepath.Base(keystorePath)
	password, err := promptForPassword(false, keystoreID)
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	ks, err := loadKeystore(keystorePath, password)
	if err != nil {
		fmt.Println("Failed to load keystore:", err)
		return
	}

	fmt.Println("Enter new data for", identifier, ":")
	newData, err := promptForData()
	if err != nil {
		fmt.Println("Error reading new data:", err)
		return
	}

	encryptedData, err := encrypt(newData, password)
	if err != nil {
		fmt.Println("Error encrypting new data:", err)
		return
	}

	ks.Passwords[identifier] = encryptedData
	saveKeystore(keystorePath, ks, password)
}

func DeleteFromKeystore(keystorePath, identifier string, keystoreName string) {
	keystoreID := filepath.Base(keystorePath)
	password, err := promptForPassword(false, keystoreID)
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	ks, err := loadKeystore(keystorePath, password)
	if err != nil {
		fmt.Println("Failed to load keystore:", err)
		return
	}

	identifier = strings.TrimSpace(identifier)
	if _, exists := ks.Passwords[identifier]; !exists {
		fmt.Println("Identifier does not exist in keystore.")
		return
	}

	delete(ks.Passwords, identifier)
	saveKeystore(keystorePath, ks, password)
	updateKeystoreIndex(keystoreName, identifier, false)
}

func CopyToClipboard(keystorePath, identifier string) {
	keystoreID := filepath.Base(keystorePath)
	setCurrentKeystoreID(keystoreID)

	password, err := promptForPassword(false, keystoreID)
	if err != nil {
		fmt.Println("Error reading password:", err)
		return
	}

	ks, err := loadKeystore(keystorePath, password)
	if err != nil {
		fmt.Println("Failed to load keystore:", err)
		return
	}

	encryptedData, exists := ks.Passwords[identifier]
	if !exists {
		fmt.Println("Identifier not found.")
		return
	}

	data, err := decrypt(encryptedData, password)
	if err != nil {
		fmt.Println("Failed to decrypt data:", err)
		return
	}

	if notErr := clipboard.WriteAll(data); notErr != nil {
		fmt.Println("Error copying to clipboard:", err)
		return
	}

	fmt.Println("Data copied to clipboard!")
	storeKeystorePassword(keystoreID, password)
}

func DeleteKeystore(keystorePath string) {
	err := os.Remove(keystorePath)
	if err != nil {
		fmt.Println("Failed to delete keystore:", err)
		return
	}
	fmt.Println("Keystore deleted successfully!")
}

func ChangeMasterPassword(keystorePath string) {
	keystoreID := filepath.Base(keystorePath)
	fmt.Println("Changing master password.")

	oldPassword, err := promptForPassword(false, keystoreID)
	if err != nil {
		fmt.Println("Failed to read old password:", err)
		return
	}

	ks, err := loadKeystore(keystorePath, oldPassword)
	if err != nil {
		fmt.Println("Failed to load keystore with old password:", err)
		return
	}

	setBypassSessionCheck(true) // Force a new password prompt
	newPassword, err := promptForPassword(true, keystoreID)
	setBypassSessionCheck(false)
	if err != nil {
		fmt.Println("Failed to set new password:", err)
		return
	}

	// Re-encrypt everything with the new password
	for id, encryptedData := range ks.Passwords {
		data, err := decrypt(encryptedData, oldPassword)
		if err != nil {
			fmt.Printf("Failed to decrypt data for %s: %v\n", id, err)
			return
		}

		newEncryptedData, err := encrypt(data, newPassword)
		if err != nil {
			fmt.Printf("Failed to re-encrypt data for %s: %v\n", id, err)
			return
		}

		ks.Passwords[id] = newEncryptedData
	}

	saveKeystore(keystorePath, ks, newPassword)
	storeKeystorePassword(keystoreID, newPassword)
	fmt.Println("Master password changed successfully")
}

func storeKeystorePassword(keystoreID, password string) {
	passwordKey := "keystorePassword_" + keystoreID
	timestampKey := "timestamp_" + keystoreID

	utils.SetKeyringItem(passwordKey, []byte(password))
	utils.SetKeyringItem(timestampKey, []byte(time.Now().Format(time.RFC3339)))
}

func getKeystorePassword(keystoreID string) (string, error) {
	passwordKey := "keystorePassword_" + keystoreID
	timestampKey := "timestamp_" + keystoreID

	tsData, err := utils.GetKeyringItem(timestampKey)
	if err != nil {
		return "", fmt.Errorf("could not find timestamp in keyring: %v", err)
	}

	timestamp, err := time.Parse(time.RFC3339, string(tsData))
	if err != nil {
		return "", fmt.Errorf("could not parse timestamp: %v", err)
	}

	if time.Since(timestamp) > 20*time.Minute {
		utils.RemoveKeyringItem(passwordKey)
		utils.RemoveKeyringItem(timestampKey)
		return "", fmt.Errorf("session expired")
	}

	pwData, err := utils.GetKeyringItem(passwordKey)
	if err != nil {
		return "", fmt.Errorf("could not find password in keyring: %v", err)
	}

	return string(pwData), nil
}
