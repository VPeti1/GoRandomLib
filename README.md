# GoRandomLib
A collection of useful yet random go funtions in one libary

# Functions

1. `extractValue(content, key string) string`: Extracts a value from a string `content` based on a given `key`. It splits the `content` string using the `key`, then returns the first word after the key.

2. `dirExists(path string) bool`: Checks if a directory exists at the specified `path`.

3. `readFile(filename string) (string, error)`: Reads the content of a file specified by `filename` and returns it as a string. It also returns an error if any.

4. `getChars(s string, num int) string`: Returns the first `num` characters from the string `s`.

5. `CreateSHA256String(input string) string`: Calculates the SHA-256 hash of the input string and returns it as a hexadecimal string.

6. `RandomStringWithCharset(length int, charset string) string`: Generates a random string of the specified `length` using the provided `charset`.

7. `RandomString(length int) string`: Generates a random string of the specified `length` using the default charset defined in the package.

8. `removeChars(s string, num int) string`: Removes `num` characters from the beginning and end of the string `s`.

9. `detectOS() string`: Detects the operating system and returns its name ("linux" or "windows").

10. `errcode(error string)`: Prints an error message along with an exit code and terminates the program.

11. `getid() []byte`: Gets the machine ID used for encryption. It returns the machine ID as a byte slice.

12. `getidforencl() []byte`: Retrieves the machine ID from the "/etc/machine-id" file and generates a valid AES key from it. It returns the AES key as a byte slice.

13. `getIDForEncryptionw() (string, error)`: Retrieves the MAC address of the first non-loopback network interface on a Windows system. It returns the MAC address as a string or an error if it fails.

14. `userroot() bool`: Checks if the current user is the root user.

15. `encryptyaenss(data []byte) (string, error)`: Encrypts data using AES encryption with a key derived from the machine ID. It returns the encrypted data as a base64-encoded string or an error if encryption fails.

16. `decryptyaenss(encrypted string) (string, error)`: Decrypts data encrypted using AES encryption with a key derived from the machine ID. It returns the decrypted data as a string or an error if decryption fails.

17. `listPasswords(passfile string)`: Reads a password file, decrypts the passwords stored in it, and prints the service and decrypted password pairs.

18. `encrypt(data []byte) (string, error)`: Encrypts data using AES encryption with a key derived from the machine ID. It returns the encrypted data as a base64-encoded string or an error if encryption fails.
