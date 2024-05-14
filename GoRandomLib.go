package randlib

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
)

const charset = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

func extractValue(content, key string) string {
	if strings.Contains(content, key) {
		return strings.Fields(strings.Split(content, key)[1])[0]
	}
	return ""
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func readFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func getChars(s string, num int) string {
	if len(s) < num {
		return s
	}
	return s[:num]
}

func CreateSHA256String(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hash := hasher.Sum(nil)
	hashstring := hex.EncodeToString(hash)
	return string(hashstring)
}

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		random, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[random.Int64()]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}

func removeChars(s string, num int) string {
	if len(s) < num {
		return ""
	}
	return s[num : len(s)-num]
}

func detectOS() string {
	if runtime.GOOS == "linux" {
		return "linux"
	}
	return "windows"
}

func errcode(error string) {
	fmt.Println("Program failed with exit code: " + error)
	log.Fatal(error)
	return
}

func getid() (ret []byte) {
	if detectOS() == "linux" {
		ret := getidforencl()
		return ret
	} else {
		rets, err := getIDForEncryptionw()
		if err != nil {
			return
		}
		ret := []byte(rets)
		return ret
	}
}

func getIDForEncryptionw() (string, error) {
	// Get the MAC address of the first non-loopback network interface
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, intf := range interfaces {
		if intf.Flags&net.FlagLoopback == 0 && intf.HardwareAddr != nil {
			return strings.Replace(intf.HardwareAddr.String(), ":", "", -1), nil
		}
	}

	return "", fmt.Errorf("MAC address not found")
}

// Function to get the machine ID and generate a valid AES key
func getidforencl() []byte {
	// Open the /etc/machine-id file
	file, err := os.Open("/etc/machine-id")
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}
	defer file.Close()

	// Read the content of /etc/machine-id file
	machineID := make([]byte, 100) // Adjust the buffer size accordingly
	_, err = file.Read(machineID)
	if err != nil {
		fmt.Println("Error:", err)
		return nil
	}

	// Compute SHA-256 hash of the machine ID
	hash := sha256.New()
	hash.Write(machineID)
	hashBytes := hash.Sum(nil)

	// Take the first 32 bytes of the hash as the AES key
	aesKey := hashBytes[:32]

	return aesKey
}

func userroot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

func encryptyaenss(data []byte) (string, error) {
	key := getid()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt function
func decryptyaenss(encrypted string) (string, error) {
	key := getid()

	// Decode the base64-encoded ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func listPasswords(passfile string) {
	// Open the password file for reading
	file, err := os.Open(passfile)
	if err != nil {
		fmt.Println("Error opening password file:", err)
		return
	}
	defer file.Close()

	// Read passwords from the file and print them
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			service, encryptedPassword := parts[0], parts[1]

			// Decrypt the password
			decryptedPassword, err := decryptyaenss(encryptedPassword)
			if err != nil {
				fmt.Println("Error decrypting password:", err)
				return
			}

			fmt.Printf("Service: %s, Password: %s\n", service, decryptedPassword)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading password file:", err)
		return
	}
}

// Encrypt function
func encrypt(data []byte) (string, error) {
	key := getid()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
