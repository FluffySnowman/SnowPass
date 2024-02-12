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

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"

	"github.com/fluffysnowman/snowpass/models"
	// "github.com/fluffysnowman/snowpass/utils"
	"time"

	"github.com/99designs/keyring"
	"github.com/fluffysnowman/snowpass/states"
)

type Keystore models.Keystore

var dataDir = states.GlobalDataDirectory

// keystore id states since I don't want to refactor everything

var currentKeystoreID string

func setCurrentKeystoreID(keystoreID string) {
	currentKeystoreID = keystoreID
}

func getCurrentKeystoreID() string {
	return currentKeystoreID
}

// session checking for whether to prompt for password or not
// based on the time or when the password is required or not

var bypassSessionCheck bool

func setBypassSessionCheck(bypass bool) {
	bypassSessionCheck = bypass
}

// password session keyring init
var ring keyring.Keyring

func init() {
	ring, _ = keyring.Open(keyring.Config{
		ServiceName: "snowpass",
	})
}

func promptForPassword(verify bool) (string, error) {
	if !bypassSessionCheck {
		password, err := getKeystorePassword()
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
		storeKeystorePassword(strings.TrimSpace(password))
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

	password, err := promptForPassword(true)
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

	password, err := promptForPassword(false)
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

	password, err := promptForPassword(false)
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
	storeKeystorePassword(password)
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
		// remove the thing from the index since it wasn't working before
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
	return filepath.Join(dataDir, keystoreName+"_index.json")
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
			// fmt.Printf("%v%s\n", color.BlueString("└── "), keystoreName)
			listKeystore(keystoreName)
		}
	}

	// for debugging
	fmt.Println("\n\n========== DEBUG ============")
	fmt.Println("data directory location (for bedugging) (may not work on windows)")
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

func editInKeystore(keystorePath, identifier string) {
	password, err := promptForPassword(false)
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
	password, err := promptForPassword(false)
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

	password, err := promptForPassword(false)
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
	storeKeystorePassword(password)
}

func EditInKeystore(keystorePath, identifier string) {
	password, err := promptForPassword(false)
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

func DeleteKeystore(keystorePath string) {
	err := os.Remove(keystorePath)
	if err != nil {
		fmt.Println("Failed to delete keystore:!!!!!!!bruh", err)
		return
	}
	fmt.Println("Keystore deleted successfully!")
}

func ChangeMasterPassword(keystorePath string) {
	fmt.Println("Changing master password.")

	fmt.Print("Enter old master password: ")
	oldPasswordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to read old password:", err)
		return
	}
	fmt.Println()
	oldPassword := string(oldPasswordBytes)

	ks, err := loadKeystore(keystorePath, oldPassword)
	if err != nil {
		fmt.Println("Failed to load keystore with old password:", err)
		return
	}

	fmt.Print("Enter new master password: ")
	newPasswordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to read new password:", err)
		return
	}
	fmt.Println()

	fmt.Print("Verify new master password: ")
	verifyNewPasswordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("Failed to verify new password:", err)
		return
	}
	fmt.Println()

	newPassword := string(newPasswordBytes)
	verifyNewPassword := string(verifyNewPasswordBytes)

	if newPassword != verifyNewPassword {
		fmt.Println("passwords do not match (*verification).")
		return
	}

	// re-encrypting everything so that we don't lose everything (hopefully)
	for id, encryptedData := range ks.Passwords {
		data, err := decrypt(encryptedData, oldPassword)
		if err != nil {
			fmt.Printf("Failed to decrypt data for %s: %v\n", id, err)
			return
		}

		// encrypting everything again
		newEncryptedData, err := encrypt(data, newPassword)
		if err != nil {
			fmt.Printf("Failed to re-encrypt data for %s: %v\n", id, err)
			return
		}

		// updating thekeystore
		ks.Passwords[id] = newEncryptedData
	}

	// re-updateu everything with the changed thing
	saveKeystore(keystorePath, ks, newPassword)
	fmt.Println("Master password changed successfully")
}

func storeKeystorePassword(password string) {
	keystoreID := getCurrentKeystoreID()
	passwordKey := "keystorePassword_" + keystoreID
	timestampKey := "timestamp_" + keystoreID

	_ = ring.Set(keyring.Item{
		Key:  passwordKey,
		Data: []byte(password),
	})

	_ = ring.Set(keyring.Item{
		Key:  timestampKey,
		Data: []byte(time.Now().Format(time.RFC3339)),
	})
}

func getKeystorePassword() (string, error) {
	keystoreID := getCurrentKeystoreID()
	passwordKey := "keystorePassword_" + keystoreID
	timestampKey := "timestamp_" + keystoreID

	tsItem, err := ring.Get(timestampKey)
	if err != nil {
		return "", fmt.Errorf("could not find timestamp in keyring: %v", err)
	}

	timestamp, err := time.Parse(time.RFC3339, string(tsItem.Data))
	if err != nil {
		return "", fmt.Errorf("could not parse timestamp: %v", err)
	}

	if time.Since(timestamp) > 20*time.Minute {
		_ = ring.Remove(passwordKey)
		_ = ring.Remove(timestampKey)
		return "", fmt.Errorf("session expired")
	}

	pwItem, err := ring.Get(passwordKey)
	if err != nil {
		return "", fmt.Errorf("could not find password in keyring: %v", err)
	}

	return string(pwItem.Data), nil
}
