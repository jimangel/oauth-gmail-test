package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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

	// request the SEND scope via gmail API from user
	config, err = google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
}

// startLocalServer starts a local HTTP server to listen for OAuth callback.
func startLocalServer(config *oauth2.Config) (chan string, string) {
	listener, err := net.Listen("tcp", "localhost:0") // Listens on a random port on localhost.
	if err != nil {
		log.Fatalf("Failed to listen on a port: %v", err) // Logs fatal error if listening fails.
	}
	port := listener.Addr().(*net.TCPAddr).Port // Retrieves the chosen port.
	authCodeChannel := make(chan string)        // Channel to pass the authorization code.

	redirectURL := fmt.Sprintf("http://localhost:%v/", port) // Sets the redirect URL for the OAuth2 flow.
	config.RedirectURL = redirectURL                         // Updates the OAuth2 config with the redirect URL.

	// Goroutine to handle the HTTP request and extract the authorization code.
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Authentication successful! You may now close this window.") // Response to the user.
		authCodeChannel <- r.URL.Query().Get("code")                                 // Sends the authorization code to the channel.
	}))

	return authCodeChannel, redirectURL
}

// openBrowser tries to open the authentication URL in the user's web browser.
func openBrowser(url string, noBrowser bool) {
	if noBrowser {
		// If --no-browser flag is set, outputs the URL to the console instead of opening a browser.
		fmt.Println("Open the following URL in your browser and authorize the application:")
		fmt.Printf("\033[1;34m%s\033[0m\n", url) // Prints the URL in blue color.
		fmt.Println("\nIgnore the 'This site can't be reached / localhost refused to connect' error, and copy the full URL from the browser's address bar and paste it here.")
		return
	}

	var err error
	// Opens the URL in a web browser based on the user's operating system.
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
		log.Fatalf("Unable to open browser: %v", err) // Logs fatal error if opening the browser fails.
	}
}

// getTokenFromWeb handles the OAuth authentication flow and retrieves the token.
func getTokenFromWeb(config *oauth2.Config, authCodeChannel chan string, noBrowser bool) *oauth2.Token {
	var authURL string
	// Generates the authentication URL with or without state token based on the --no-browser flag.
	if noBrowser {
		authURL = config.AuthCodeURL("", oauth2.AccessTypeOffline)
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("Unable to generate state token: %v", err) // Logs fatal error if state token generation fails.
		}
		stateToken := base64.URLEncoding.EncodeToString(b)
		authURL = config.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
	}

	openBrowser(authURL, noBrowser) // Opens the authentication URL in the browser.

	var authCode string
	if noBrowser {
		// Handles manual input of the authorization code if the --no-browser flag is set.
		fmt.Println("Enter the full redirect URL from your browser:")
		var redirectURL string
		_, err := fmt.Scan(&redirectURL)
		if err != nil {
			log.Fatalf("Failed to read input: %v", err) // Logs fatal error if input reading fails.
		}

		parsedURL, err := url.Parse(redirectURL)
		if err != nil {
			log.Fatalf("Failed to parse redirect URL: %v", err) // Logs fatal error if URL parsing fails.
		}
		authCode = parsedURL.Query().Get("code")
		if authCode == "" {
			log.Fatal("Authorization code not found in the URL") // Logs fatal error if authorization code is missing.
		}
	} else {
		authCode = <-authCodeChannel // Receives the authorization code from the channel.
	}

	tok, err := config.Exchange(context.Background(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err) // Logs fatal error if token exchange fails.
	}
	return tok
}

// tokenHasScopes checks if the token includes all the required scopes.
func tokenHasScopes(tok *oauth2.Token, scopes []string) bool {
	if tok == nil {
		return false // Returns false if token is nil.
	}
	grantedScopes := strings.Split(tok.Extra("scope").(string), " ") // Splits the token scopes into a slice.

	grantedScopesMap := make(map[string]bool) // Map to store the granted scopes.
	for _, scope := range grantedScopes {
		grantedScopesMap[scope] = true // Maps each granted scope to true.
	}

	// Checks if all required scopes are included in the granted scopes.
	for _, scope := range scopes {
		if !grantedScopesMap[scope] {
			return false // Returns false if any required scope is missing.
		}
	}
	return true
}

// getClient retrieves an HTTP client using the provided OAuth2 configuration.
func getClient(config *oauth2.Config, noBrowser bool) (*http.Client, error) {
	tok, err, _ := sf.Do("token", func() (interface{}, error) {
		// If token is nil or does not have required scopes, initiates the token retrieval process.
		if inMemoryToken == nil || !tokenHasScopes(inMemoryToken, config.Scopes) {
			var newToken *oauth2.Token
			if noBrowser {
				newToken = getTokenFromWeb(config, nil, noBrowser)
			} else {
				authCodeChannel, _ := startLocalServer(config)
				newToken = getTokenFromWeb(config, authCodeChannel, noBrowser)
			}
			inMemoryToken = newToken // Updates the in-memory token.
		}
		return inMemoryToken, nil
	})

	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token: %v", err) // Returns error if token retrieval fails.
	}

	return config.Client(context.Background(), tok.(*oauth2.Token)), nil // Returns the OAuth2 HTTP client.
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

// main function with flag parsing
func main() {
	noBrowserFlag := flag.Bool("no-browser", false, "Set this flag to manually enter the authorization code")
	flag.Parse()

	emailTo, err := getEmailTo()
	if err != nil {
		log.Fatal(err)
	}

	client, err := getClient(config, *noBrowserFlag)
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
