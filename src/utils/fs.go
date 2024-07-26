package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/99designs/keyring"
)

func GetAppDataDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	var appDataDir string
	switch runtime.GOOS {
	case "windows":
		appDataDir = filepath.Join(homeDir, "AppData", "Local", "snowpass")
	case "darwin":
		appDataDir = filepath.Join(homeDir, "Library", "Application Support", "snowpass")
	case "linux":
		appDataDir = filepath.Join(homeDir, ".local", "share", "snowpass")
	default:
		return "", fmt.Errorf("unsupported platform\nCreate an issue on https://github.com/fluffysnowman/snowpass with details about this")
	}

	return appDataDir, nil
}

func GetFullDataDir() string {
	appDataDir, err := GetAppDataDir()
	if err != nil {
		fmt.Println("Failed to get application data directory:", err)
		return ""
	}

	dataDir := filepath.Join(appDataDir, "_data")

	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		fmt.Println("_data directory for keystore does not exist. Creating it now.")
		if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
			fmt.Println("Failed to create _data directory:", err)
			return ""
		}
	}

	return dataDir
}

var ring keyring.Keyring

func init() {
	var err error
	ring, err = keyring.Open(keyring.Config{
		ServiceName: "snowpass",
	})
	if err != nil {
		fmt.Println("Failed to initialize keyring:", err)
		os.Exit(1)
	}
}

func SetKeyringItem(key string, data []byte) error {
	return ring.Set(keyring.Item{
		Key:  key,
		Data: data,
	})
}

func GetKeyringItem(key string) ([]byte, error) {
	item, err := ring.Get(key)
	if err != nil {
		return nil, err
	}
	return item.Data, nil
}

func RemoveKeyringItem(key string) error {
	return ring.Remove(key)
}
