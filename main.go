package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/sync/singleflight"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// set the global oauth2 vars
var (
	config        *oauth2.Config
	inMemoryToken *oauth2.Token
	sf            singleflight.Group
)

// getCredentialsFilePath retrieves the file path for OAuth 2.0 credentials (client ID / secret).
func getCredentialsFilePath() string {
	path := os.Getenv("CREDENTIALS_JSON_PATH")
	if path == "" {
		log.Fatal("Environment variable CREDENTIALS_JSON_PATH is not set.")
	}
	return path
}

// init the OAUTH credentials
func init() {
	var err error
	credentialsPath := getCredentialsFilePath()
	b, err := os.ReadFile(credentialsPath)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err = google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
}

// startLocalServer starts a local HTTP server to listen for OAuth callback.
func startLocalServer(config *oauth2.Config) (chan string, string) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		log.Fatalf("Failed to listen on a port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	authCodeChannel := make(chan string)

	redirectURL := fmt.Sprintf("http://localhost:%v/", port)
	config.RedirectURL = redirectURL

	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Authentication successful! You may now close this window.")
		authCodeChannel <- r.URL.Query().Get("code")
	}))

	return authCodeChannel, redirectURL
}

// openBrowser attempts to open the authentication URL in a web browser.
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatalf("Unable to open browser: %v", err)
	}
}

// getTokenFromWeb handles OAuth authentication flow and retrieves the token.
func getTokenFromWeb(config *oauth2.Config, authCodeChannel chan string) *oauth2.Token {
	// generateStateToken generates a random state token for OAuth authentication.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Unable to generate state token: %v", err)
	}

	stateToken := base64.URLEncoding.EncodeToString(b)
	authURL := config.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)

	openBrowser(authURL)

	authCode := <-authCodeChannel
	tok, err := config.Exchange(context.Background(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

// tokenHasScopes checks if the token includes all the required scopes.
func tokenHasScopes(tok *oauth2.Token, scopes []string) bool {
	if tok == nil {
		return false
	}
	grantedScopes := strings.Split(tok.Extra("scope").(string), " ")

	grantedScopesMap := make(map[string]bool)
	for _, scope := range grantedScopes {
		grantedScopesMap[scope] = true
	}

	for _, scope := range scopes {
		if !grantedScopesMap[scope] {
			return false
		}
	}
	return true
}

// getClient retrieves an HTTP client using the provided OAuth2 configuration.
func getClient(config *oauth2.Config) (*http.Client, error) {
	tok, err, _ := sf.Do("token", func() (interface{}, error) {
		if inMemoryToken == nil || !tokenHasScopes(inMemoryToken, config.Scopes) {
			authCodeChannel, _ := startLocalServer(config)
			newToken := getTokenFromWeb(config, authCodeChannel)
			inMemoryToken = newToken
		}
		return inMemoryToken, nil
	})

	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token: %v", err)
	}

	return config.Client(context.Background(), tok.(*oauth2.Token)), nil
}

// getEmailTo retrieves the recipient email address from an environment variable.
func getEmailTo() (string, error) {
	emailTo := os.Getenv("EMAIL_TO")
	if emailTo == "" {
		return "", fmt.Errorf("environment variable EMAIL_TO is not set")
	}
	return emailTo, nil
}

// sendTestEmail sends a test email using the Gmail service.
func sendTestEmail(service *gmail.Service, emailTo string) error {
	subject := "Subject: Test Email\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"
	body := "This is a test email sent by a Golang application."
	msg := []byte("to: " + emailTo + "\r\n" +
		"from: me\r\n" +
		subject +
		mime +
		"\r\n" + body)

	var message gmail.Message
	message.Raw = base64.URLEncoding.EncodeToString(msg)

	if _, err := service.Users.Messages.Send("me", &message).Do(); err != nil {
		return fmt.Errorf("unable to send email: %v", err)
	}
	return nil
}

func main() {
	emailTo, err := getEmailTo()
	if err != nil {
		log.Fatal(err)
	}

	client, err := getClient(config)
	if err != nil {
		log.Fatal(err)
	}

	gmailService, err := gmail.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Fatal(err)
	}

	if err := sendTestEmail(gmailService, emailTo); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Test email sent!")
}
