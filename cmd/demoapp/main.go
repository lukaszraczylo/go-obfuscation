package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"time"
)

const (
	apiKey    = "sk-proj-FAKE-KEY-1234567890abcdef"
	secretVal = "super-secret-license-key-DO-NOT-SHARE"
	dbConnStr = "postgres://admin:P@ssw0rd!@db.internal:5432/production"
	jwtSecret = "my-jwt-signing-secret-2024"
)

var licenseKey = "LIC-XXXX-YYYY-ZZZZ-PRODUCTION"

func main() {
	fmt.Println("Application started successfully")
	fmt.Printf("Version: %s\n", getVersion())
	fmt.Printf("Build:   %s\n", getBuildID())

	processRequest("user-12345")
}

func getVersion() string {
	return "1.0.0-prod"
}

func getBuildID() string {
	return fmt.Sprintf("build-%d", time.Now().Unix())
}

func processRequest(userID string) {
	fmt.Printf("Processing request for user: %s\n", userID)

	if userID == "" {
		fmt.Fprintln(os.Stderr, "Error: empty user ID")
		os.Exit(1)
	}

	token := generateToken(userID)
	fmt.Printf("Generated token: %s\n", maskString(token))

	result := validateLicense(licenseKey)
	fmt.Printf("License valid: %v\n", result)

	_ = apiKey
	_ = secretVal
	_ = dbConnStr
	_ = jwtSecret
}

func generateToken(userID string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", userID, time.Now().UnixNano())))
	return fmt.Sprintf("tok_%x", h[:8])
}

func validateLicense(key string) bool {
	return len(key) > 10
}

func maskString(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func init() {
	fmt.Println("Initializing secure environment...")
}
