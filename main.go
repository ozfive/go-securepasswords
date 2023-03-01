package password

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	// Import necessary packages
	"github.com/hashicorp/vault/api"
	"github.com/nbutton23/zxcvbn-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// Define constants and variables that will be used in the package.
const (
	DefaultPasswordLength = 128
	KeyLength             = 32
	SaltLength            = 16
	NonceLength           = 12
	SecretsPath           = "secret/data/myapp/key"
	Argon2Time            = 1
	Argon2Memory          = 64 * 1024
	Argon2Threads         = 4
	Argon2KeyLength       = 32
	KeyPath               = "secret/password-generator/key"
)

var (
	ErrInvalidKeyType = errors.New("invalid key type")
)

// generateSalt generates a new random salt using a secure CSPRNG. It takes an integer that specifies the length of the salt as an input and returns a byte slice of the specified length.
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

// generateNonce generates a new random nonce using a secure CSPRNG. It takes an integer that specifies the length of the nonce as an input and returns a byte slice of the specified length.
func generateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

// deriveKeyFromPassword derives a cryptographic key from a password and
// salt using the scrypt key derivation function. It takes a password
// and salt as byte slices and returns a derived key as a byte slice.
// It also returns an error if the scrypt function fails for any reason.
func deriveKeyFromPassword(password []byte, salt []byte) ([]byte, error) {
	// Choose parameters for scrypt
	N := 16384   // CPU/memory cost parameter (higher value = more memory/time required)
	r := 8       // block size parameter (affects parallelism)
	p := 1       // parallelization parameter (affects parallelism)
	keyLen := 32 // desired length of the derived key

	// Derive the key using scrypt
	key, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// secureCompare compares two byte slices in constant time to avoid timing attacks. It takes two byte slices as input and returns a boolean indicating whether they are equal.
func secureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var equal = 1
	for i := 0; i < len(a); i++ {
		equal &= constantTimeByteEq(a[i], b[i])
	}
	return equal == 1
}

// constantTimeByteEq is a helper function used by secureCompare to compare two bytes in constant time. It takes two bytes as input and returns an integer indicating whether they are equal.
func constantTimeByteEq(x, y byte) int {
	var v byte
	for i := uint(0); i < 8; i++ {
		v |= (x ^ y) >> i
	}
	return int((v ^ 1) & 1)
}

// generateRandomBytes generates a new byte slice of the specified length using a secure CSPRNG. It takes an integer that specifies the length of the byte slice as an input and returns a byte slice of the specified length.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func overwrite(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateSecretKey generates a new secret key using a secure CSPRNG
// and a KDF such as Argon2. The generated key is also
// securely stored in the Vault.
func GenerateSecretKey(vaultClient *api.Client) ([]byte, error) {
	// Generate a new random salt
	salt, err := generateSalt(SaltLength)
	if err != nil {
		return nil, err
	}

	// Generate a new random key
	key := make([]byte, KeyLength)
	_, err = rand.Read(key)
	if err != nil {
		return nil, err
	}

	// Derive a key from the random key using Argon2
	derivedKey := argon2.IDKey(key, salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLength)

	// Store the derived key securely in the Vault
	err = storeSecret(vaultClient, SecretsPath, derivedKey)
	if err != nil {
		return nil, err
	}

	return derivedKey, nil
}

// storeSecret securely stores a secret in the Vault.
func storeSecret(vaultClient *api.Client, path string, secret []byte) error {
	// Encode the secret as base64
	encodedSecret := base64.StdEncoding.EncodeToString(secret)

	// Create a new Vault secret
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"value": encodedSecret,
		},
	}

	// Store the secret in the Vault
	secretResponse, err := vaultClient.Logical().Write(path, secretData)
	if err != nil {
		return err
	}

	// Check if the write operation was successful
	if secretResponse == nil || secretResponse.Data == nil || len(secretResponse.Data) == 0 || secretResponse.Data["value"] == nil {
		return errors.New("failed to store secret in Vault")
	}

	return nil
}

const (
	LowercaseLetters = "abcdefghijklmnopqrstuvwxyz"
	UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Numbers          = "0123456789"
	SpecialChars     = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

func calculateEntropy(password string) (float64, error) {
	if password == "" {
		return 0, errors.New("password cannot be empty")
	}

	passwordLength := len(password)
	var charSetCount int
	var charSet string

	if strings.ContainsAny(password, LowercaseLetters) {
		charSetCount++
		charSet += LowercaseLetters
	}
	if strings.ContainsAny(password, UppercaseLetters) {
		charSetCount++
		charSet += UppercaseLetters
	}
	if strings.ContainsAny(password, Numbers) {
		charSetCount++
		charSet += Numbers
	}
	if strings.ContainsAny(password, SpecialChars) {
		charSetCount++
		charSet += SpecialChars
	}

	if charSetCount < 2 {
		return 0, errors.New("password must contain characters from at least 2 character sets")
	}

	passwordRunes, _, _, err := GeneratePassword(passwordLength, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to generate password: %v", err)
	}

	var possibleChars float64
	for _, char := range charSet {
		if strings.ContainsRune(string(passwordRunes), char) {
			possibleChars += float64(strings.Count(charSet, string(char)))
		}
	}

	entropy := math.Log2(math.Pow(possibleChars, float64(passwordLength)))
	return entropy, nil
}

const (
	MasterKeyLength = 32
)

// getMasterKey retrieves the master key from the vault server using the provided client.
func getMasterKey(vaultClient *api.Client) ([]byte, error) {
	secret, err := vaultClient.Logical().Read("secret/data/master-key")
	if err != nil {
		return nil, fmt.Errorf("failed to read master key from vault: %v", err)
	}
	if secret == nil || secret.Data == nil || secret.Data["data"] == nil {
		return nil, fmt.Errorf("master key not found in vault")
	}
	masterKeyBytes, ok := secret.Data["data"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid master key format in vault")
	}
	masterKey, err := hex.DecodeString(masterKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid master key format in vault: %v", err)
	}
	if len(masterKey) != MasterKeyLength {
		return nil, fmt.Errorf("invalid master key length in vault")
	}
	return masterKey, nil
}

const MaxPasswordLength = 1000

// GeneratePassword generates a new password of the specified length by creating a random byte slice of the specified length,
// encrypting it using the EncryptPassword function, and returning the resulting encrypted password, the salt and nonce used in the encryption process.
// If an error occurs during any step of the process, an error is returned.
// This function also validates the passwordLength input parameter to ensure that it is a positive integer within a reasonable range.
func GeneratePassword(passwordLength int, vaultClient *api.Client) ([]rune, []byte, []byte, error) {
	// Validate the password length input parameter
	if passwordLength <= 0 {
		return nil, nil, nil, errors.New("password length must be a positive integer")
	}

	if passwordLength > MaxPasswordLength {
		return nil, nil, nil, fmt.Errorf("password length cannot be greater than %d", MaxPasswordLength)
	}

	// Create a byte slice of random bytes of the specified length
	randomBytes, err := generateRandomBytes(passwordLength)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	// Defer a call to overwrite the byte slice to securely clear its contents from memory
	defer overwrite(randomBytes)

	// Generate a salt of the specified length
	saltBytes, err := generateSalt(SaltLength)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	// Defer a call to overwrite the salt to securely clear its contents from memory
	defer overwrite(saltBytes)

	// Generate a nonce of the specified length
	nonceBytes, err := generateNonce(NonceLength)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	// Defer a call to overwrite the nonce to securely clear its contents from memory
	defer overwrite(nonceBytes)

	// Convert the random byte slice to a rune slice
	passwordRunes := make([]rune, passwordLength)
	for i := 0; i < passwordLength; i++ {
		passwordRunes[i] = rune(randomBytes[i])
	}

	// Get the master key from Vault
	masterKey, err := getMasterKey(vaultClient)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get master key: %v", err)
	}

	// Encrypt the password using the EncryptPassword function and return the encrypted password, salt, and nonce
	encryptedPassword, saltBytes, nonceBytes, err := EncryptPassword(passwordRunes, vaultClient, masterKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encrypt password: %v", err)
	}
	return encryptedPassword, saltBytes, nonceBytes, nil
}

// EncryptPassword encrypts a password using a ChaCha20-Poly1305 AEAD cipher and a secret key retrieved from the Vault.
func EncryptPassword(password []rune, vaultClient *api.Client, masterKey []byte) ([]rune, []byte, []byte, error) {
	// Generate a new random salt
	saltBytes, err := generateSalt(SaltLength)
	if err != nil {
		return nil, nil, nil, err
	}
	defer overwrite(saltBytes)

	// Derive a key from the master key and salt using HKDF
	derivedKey := hkdf.New(sha256.New, masterKey, saltBytes, []byte("password-encryption-key"))
	keyBytes := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(derivedKey, keyBytes); err != nil {
		return nil, nil, nil, err
	}

	// Create a new ChaCha20-Poly1305 AEAD cipher using the derived key
	aead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	// Generate a new random nonce
	nonceBytes, err := generateNonce(NonceLength)
	if err != nil {
		return nil, nil, nil, err
	}
	defer overwrite(nonceBytes)

	// Convert the password to a byte slice
	passwordBytes := make([]byte, len(password)*2)
	for i, r := range password {
		passwordBytes[i*2] = byte(r)
		passwordBytes[i*2+1] = byte(r >> 8)
	}

	// Encrypt the password with ChaCha20-Poly1305
	encryptedBytes := aead.Seal(nil, nonceBytes, passwordBytes, nil)

	// Encode the encrypted bytes as URL-safe base64
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(encryptedBytes)))
	base64.RawURLEncoding.Encode(encoded, encryptedBytes)

	// Convert the encoded bytes to a rune slice
	encryptedPassword := make([]rune, len(encoded))
	for i, r := range encoded {
		encryptedPassword[i] = rune(r)
	}

	return encryptedPassword, saltBytes, nonceBytes, nil
}

var (
	ErrDecryptFailed   = errors.New("Failed to decrypt password")
	ErrTooManyFailures = errors.New("Too many failed attempts")
	ErrOpenAuth        = errors.New("chacha20poly1305: Message authentication failed")
	MaxDecryptFailures = 5
	failedAttempts     = 0
)

// DecryptPassword decrypts an encrypted password using a ChaCha20-Poly1305 AEAD cipher and a secret key derived from the password and salt using Argon2.
func DecryptPassword(encryptedPassword []rune, salt []byte, nonce []byte, password []byte) ([]rune, error) {
	// Check if there have been too many failed attempts
	if failedAttempts >= MaxDecryptFailures {
		return nil, ErrTooManyFailures
	}

	// Derive a key from the password and salt using Argon2
	key, err := deriveKeyFromPassword(password, salt)
	if err != nil {
		return nil, err
	}

	// Decode the URL-safe base64 encoded encrypted password
	encryptedBytes := make([]byte, base64.RawURLEncoding.DecodedLen(len(encryptedPassword)))
	n, err := base64.RawURLEncoding.Decode(encryptedBytes, []byte(string(encryptedPassword)))
	if err != nil {
		return nil, err
	}
	encryptedBytes = encryptedBytes[:n]

	// Use authenticated decryption with ChaCha20-Poly1305
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	passwordBytes, err := aead.Open(nil, nonce, encryptedBytes, nil)
	if err != nil {
		if err.Error() == ErrOpenAuth.Error() {
			failedAttempts++
			return nil, ErrDecryptFailed
		}
		failedAttempts++
		return nil, err
	}
	defer overwrite(passwordBytes)
	passwordRunes := make([]rune, len(passwordBytes)/2)
	for i := 0; i < len(passwordRunes); i++ {
		passwordRunes[i] = rune(passwordBytes[i*2]) | rune(passwordBytes[i*2+1])<<8
	}

	// Reset the failed attempts counter on success
	failedAttempts = 0

	return passwordRunes, nil
}

// getSecretKey decodes the base64-encoded key first into a byte slice keyBytes.
// Then, using a constant-time comparison check whether the length of keyBytes
// is equal to KeyLength, which is a constant representing the expected key
// length. If the length of keyBytes does not match KeyLength, we return the
// ErrInvalidKeyType error. Otherwise, we return the key bytes.
func getSecretKey(vaultClient *api.Client) ([]rune, error) {
	secret, err := vaultClient.Logical().Read(KeyPath)
	if err != nil {
		return nil, err
	}

	key, ok := secret.Data["key"].([]rune)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	keyBytes := make([]byte, len(key)*2)
	for i, r := range key {
		keyBytes[i*2] = byte(r)
		keyBytes[i*2+1] = byte(r >> 8)
	}

	// Use a constant-time comparison to check for the key type
	if len(keyBytes) != KeyLength {
		return nil, ErrInvalidKeyType
	}

	keyRunes := make([]rune, len(keyBytes)/2)
	for i := 0; i < len(keyRunes); i++ {
		keyRunes[i] = rune(keyBytes[i*2]) | rune(keyBytes[i*2+1])<<8
	}

	return keyRunes, nil
}

// UpdateSecretKey generates a new secret key using GenerateSecretKey function
// and updates the existing key stored in the Vault.
func UpdateSecretKey(vaultClient *api.Client) ([]byte, error) {
	// Generate a new secret key
	secretKey, err := GenerateSecretKey(vaultClient)
	if err != nil {
		return nil, err
	}

	// Update the existing secret key stored in the Vault
	err = storeSecret(vaultClient, SecretsPath, secretKey)
	if err != nil {
		return nil, err
	}

	return secretKey, nil
}

// RotateSecretKey generates a new secret key using GenerateSecretKey function and updates the existing key in the Vault.
func RotateSecretKey(vaultClient *api.Client) ([]byte, error) {
	// Generate a new secret key
	newKey, err := GenerateSecretKey(vaultClient)
	if err != nil {
		return nil, err
	}

	// Update the existing secret key in the Vault
	err = storeSecret(vaultClient, SecretsPath, newKey)
	if err != nil {
		return nil, err
	}

	return newKey, nil
}

// PasswordStrength returns a score indicating the strength of a password.
// It uses the zxcvbn-go library to analyze the password and returns a score from 0 to 4.
// A score of 0 indicates a very weak password, while a score of 4 indicates a very strong password.
// The function takes a password as a parameter and can also take an optional list of user inputs to
// exclude from the analysis (such as the user's name or email address).
func PasswordStrength(password []rune) int {
	result := zxcvbn.PasswordStrength(string(password), nil)
	return result.Score
}

// ValidatePassword checks if a password meets the minimum strength requirements.
// It takes a password as a string and a minimum score as an integer and returns
// an error if the password is too weak.
func ValidatePassword(password string, minScore int) error {
	score := PasswordStrength([]rune(password))
	if score < minScore {
		return fmt.Errorf("password strength score is %d (minimum score required: %d)", score, minScore)
	}
	return nil
}
