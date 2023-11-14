package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
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

// init the OAUTH credentials
func init() {
	var err error
	var b []byte

	// Predefined secret name - can be modified as needed
	const secretName = "oauth-gmail-test-client-secret"

	// Directly retrieve the credentials file path from the environment variable
	credentialsPath := os.Getenv("CREDENTIALS_JSON_PATH")
	if credentialsPath != "" {
		if _, err := os.Stat(credentialsPath); err == nil {
			// If credentials.json file exists, read from file
			b, err = os.ReadFile(credentialsPath)
			if err != nil {
				log.Fatalf("Unable to read client secret file: %v", err)
			}
		} else {
			// Handle the case where the file does not exist
			log.Fatalf("File not found at path: %s", credentialsPath)
			// Additional handling for missing file can be added here
		}
	}

	if b == nil {
		// If no credentials from file, fetch from Google Secret Manager
		ctx := context.Background()
		b, err = getCredentialsFromSecretManager(ctx, secretName)
		if err != nil {
			log.Fatalf("Unable to read credentials from Secret Manager: %v", err)
		}
	}

	// Request the SEND scope via gmail API from user
	config, err = google.ConfigFromJSON(b, gmail.GmailSendScope)
	if err != nil {
		log.Fatalf("Unable to parse credentials to config: %v", err)
	}
}

// getCredentialsFromSecretManager retrieves credentials from Google Secret Manager.
func getCredentialsFromSecretManager(ctx context.Context, secretID string) ([]byte, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to setup secretmanager client: %v", err)
	}
	defer client.Close()

	// Retrieve the project ID from an environment variable
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		return nil, fmt.Errorf("GOOGLE_CLOUD_PROJECT environment variable is not set")
	}

	// Construct the resource name of the secret version.
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", projectID, secretID)

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %v", err)
	}

	return result.Payload.Data, nil
}

// startLocalServer starts a local HTTP server to listen for OAuth callback.
func startLocalServer(config *oauth2.Config) (chan string, string) {
	listener, err := net.Listen("tcp", "localhost:0") // Listens on a random port on localhost.
	if err != nil {
		log.Fatalf("Failed to listen on a port: %v", err)
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

// openBrowser opens the authentication URL in the user's web browser.
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
		log.Fatalf("Unable to open browser: %v", err)
	}
}

// getTokenFromWeb handles the OAuth authentication flow and retrieves the token.
// To prevent a refresh token from being issued, you should use oauth2.AccessTypeOnline instead of oauth2.AccessTypeOffline.
// This indicates that your application does not require offline access and thus does not need a refresh token.
func getTokenFromWeb(config *oauth2.Config, authCodeChannel chan string, noBrowser bool) *oauth2.Token {
	var authURL string
	// Generates the authentication URL without requesting offline access
	if noBrowser {
		authURL = config.AuthCodeURL("", oauth2.AccessTypeOnline)
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("Unable to generate state token: %v", err)
		}
		stateToken := base64.URLEncoding.EncodeToString(b)
		authURL = config.AuthCodeURL(stateToken, oauth2.AccessTypeOnline)
	}

	openBrowser(authURL, noBrowser) // Opens the authentication URL in the browser.

	var authCode string
	if noBrowser {
		// Handles manual input of the authorization code if the --no-browser flag is set.
		fmt.Println("Enter the full redirect URL from your browser:")
		var redirectURL string
		_, err := fmt.Scan(&redirectURL)
		if err != nil {
			log.Fatalf("Failed to read input: %v", err)
		}

		parsedURL, err := url.Parse(redirectURL)
		if err != nil {
			log.Fatalf("Failed to parse redirect URL: %v", err)
		}
		authCode = parsedURL.Query().Get("code")
		if authCode == "" {
			log.Fatal("Authorization code not found in the URL")
		}
	} else {
		authCode = <-authCodeChannel // Receives the authorization code from the channel.
	}

	tok, err := config.Exchange(context.Background(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web: %v", err)
	}

	// FOR DEBUG
	// Check if the token has an expiry time set
	if !tok.Expiry.IsZero() {
		// Calculate the duration until the token expires
		timeLeft := time.Until(tok.Expiry)
		fmt.Printf("Token is valid for: %v\n", timeLeft)
		fmt.Printf("TokenType: %s\n", tok.TokenType)
		if tok.RefreshToken == "" {
			fmt.Println("RefreshToken: nil")
		} else {
			fmt.Printf("RefreshToken: %s\n", tok.RefreshToken)
		}
		fmt.Printf("Expiry: %v\n", tok.Expiry)
	} else {
		// Handle the case where the token does not expire
		fmt.Println("This token does not have an expiration time.")
	}
	// Fetch token information from Google's tokeninfo endpoint
	tokenInfo, err := fetchTokenInfo(tok.AccessToken)
	if err != nil {
		fmt.Printf("Error fetching token info: %v\n", err)
	} else {
		prettyJSON, err := json.MarshalIndent(tokenInfo, "", "    ")
		if err != nil {
			fmt.Printf("Failed to generate pretty JSON: %v\n", err)
		} else {
			fmt.Printf("Access token contents:\n%s\n\n", prettyJSON)
		}
	}

	return tok
}

// FOR DEBUG
// fetchTokenInfo makes an HTTP request to Google's tokeninfo endpoint and returns the token information.
func fetchTokenInfo(accessToken string) (map[string]interface{}, error) {
	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?access_token=" + accessToken)
	if err != nil {
		return nil, fmt.Errorf("error making request to tokeninfo endpoint: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("error unmarshaling token info: %v", err)
	}

	return data, nil
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

// readHTMLTemplate reads an HTML file and returns its content.
func readHTMLTemplate(filePath string) (string, error) {
	htmlData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("unable to read HTML template: %v", err)
	}
	return string(htmlData), nil
}

// sendTestEmail sends a test email using the Gmail service with HTML content.
func sendTestEmail(service *gmail.Service, emailTo, htmlFilePath string) error {
	htmlContent, err := readHTMLTemplate(htmlFilePath)
	if err != nil {
		return err
	}

	subject := "Subject: Test Email\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	msg := []byte("to: " + emailTo + "\r\n" +
		"from: me\r\n" +
		subject +
		mime +
		"\r\n" + htmlContent)

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

	htmlTemplatePath := "template.html" // Update this path as needed

	if err := sendTestEmail(gmailService, emailTo, htmlTemplatePath); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Test email sent!")
}
