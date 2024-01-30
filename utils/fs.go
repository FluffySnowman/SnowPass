package utils

import (
  "fmt"
  "os"
  "path/filepath"
  "runtime"

	// "github.com/fluffysnowman/snowpass/states"
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
    return "", fmt.Errorf("unsupported platform\nCreate on issue on https://github.com/fluffysnowman/snowpass with details about this")
	}

	return appDataDir, nil
}

func GetFullDataDir() (string) {
  appDataDir, err := GetAppDataDir()
  if err != nil {
    fmt.Println("Failed to get application data directory:", err)
    return ""
  }

  dataDir := filepath.Join(appDataDir, "_data")

  if _, err := os.Stat(dataDir); os.IsNotExist(err) {
    fmt.Println("_data directory for keystore does not not exist. Creating it now.")
    if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
      fmt.Println("Failed to create _data directory:", err)
      return ""
    }
  }

  return dataDir
}
