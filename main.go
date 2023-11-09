package main

import (
	"context"
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

var (
	config        *oauth2.Config
	inMemoryToken *oauth2.Token
	sf            singleflight.Group
)

func getCredentialsFilePath() string {
	// Use an environment variable to get the path
	path := os.Getenv("CREDENTIALS_JSON_PATH")
	if path == "" {
		log.Fatal("The environment variable CREDENTIALS_JSON_PATH is not set.")
	}
	return path
}

func startLocalServer(config *oauth2.Config) (chan string, string) {
	listener, err := net.Listen("tcp", "localhost:0") // "0" to auto-select an available port
	if err != nil {
		log.Fatalf("Failed to listen on a port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	authCodeChannel := make(chan string)

	// Create the redirect URL based on the selected port and update the config
	redirectURL := fmt.Sprintf("http://localhost:%v/", port)
	config.RedirectURL = redirectURL

	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Authentication successful! You may now close this window.")
		authCodeChannel <- r.URL.Query().Get("code")
	}))

	return authCodeChannel, redirectURL
}

// getClient uses an in-memory token instead of a file.
func getClient(config *oauth2.Config) *http.Client {
	tok, err, _ := sf.Do("token", func() (interface{}, error) {
		if inMemoryToken == nil || !tokenHasScopes(inMemoryToken, config.Scopes) {
			authCodeChannel, _ := startLocalServer(config)
			newToken := getTokenFromWeb(config, authCodeChannel)
			inMemoryToken = newToken
		}
		return inMemoryToken, nil
	})

	if err != nil {
		log.Fatalf("Unable to retrieve token: %v", err)
	}

	return config.Client(context.Background(), tok.(*oauth2.Token))
}

// tokenHasScopes checks if the token includes all the required scopes.
func tokenHasScopes(tok *oauth2.Token, scopes []string) bool {
	if tok == nil {
		return false
	}
	var grantedScopes []string
	if scopeStr, ok := tok.Extra("scope").(string); ok {
		grantedScopes = strings.Split(scopeStr, " ")
	} else {
		return false
	}

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

func getTokenFromWeb(config *oauth2.Config, authCodeChannel chan string) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	openBrowser(authURL)
	fmt.Printf("Authorize this app at this URL: %s", authURL)

	// Listen for the authorization code on the authCodeChannel
	authCode := <-authCodeChannel

	tok, err := config.Exchange(context.Background(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}
	return tok
}

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
		log.Fatalf("Unable to open browser %v", err)
	}
}

func sendTestEmail(service *gmail.Service) {
	var message gmail.Message

	emailTo := "REPLACE_ME@EXAMPLE.COM" // Set the recipient's email address here
	subject := "Subject: Test Email\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"
	body := "This is a test email sent by a Golang application."
	msg := []byte("to: " + emailTo + "\r\n" +
		"from: me\r\n" + // Use "me" as the sender
		subject +
		mime +
		"\r\n" + body)

	message.Raw = base64.URLEncoding.EncodeToString(msg)

	// Send the email
	_, err := service.Users.Messages.Send("me", &message).Do()
	if err != nil {
		log.Fatalf("Unable to send email %v", err)
	}

	fmt.Println("Test email sent!")
}

func main() {
	credentials := getCredentialsFilePath()

	b, err := os.ReadFile(credentials)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err = google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	client := getClient(config)

	srv, err := gmail.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Gmail client: %v", err)
	}

	// Since we don't have the email scope, we will not be able to retrieve the user's email address.
	// Thus, you need to set the user's email address manually or through another mechanism.
	//userEmail := "user@example.com" // Replace with the actual email address or retrieve it from another source

	sendTestEmail(srv)
}
