# oauth-gmail-test

A demo, with limited scope, allowing a local application to send emails on behalf of your personal gmail account via Google OAuth.

## High-level flow:

1) The application gets a GCP OAuth config file from `$CREDENTIALS_JSON_PATH` or looks to Google Secret Manager (using your `gcloud` credentials)
1) Launches a browser to prompt login, unless `--no-browser` is set

   ![](img/oauth-consent.png)

1) User authenticates using the URL flow, if using `--no-browser`, copy response URL back to the terminal
1) A test email is sent (using `./template.html` as the body) on the recipients behalf (using a special variable "me" representing the authenticated user) to the `$EMAIL_TO` env var.

> There is a low quotas on sending gmail messages this way. Do not use for bulk sending.

## Setup

Assumes you already have a Google Cloud Project.

- Edit the `template.html` according to your use case or update `main.go`
- Enable gmail API in the project: `gcloud services enable gmail.googleapis.com`
- Create a GCP oauth consent page (https://developers.google.com/workspace/marketplace/configure-oauth-consent-screen)
- Generate OAuth credentials for a "Desktop App" and save the file
  - Select the Credentials tab, click the Create credentials button and select OAuth client ID.
  - Select the application type Desktop app, enter a descriptive name, and click the Create button.
  - Click the file_download (Download JSON) button.
  - Rename your secret file to credentials.json.
  - Optional: `chmod 600 /path/to/your/credentials.json`

Optional use of Google Secret Manager:

```
# enable the Google Secret Manager API
gcloud services enable secretmanager.googleapis.com

# create a new secret
gcloud secrets create oauth-gmail-test-client-secret --replication-policy="automatic"

# use your credentials file created above
gcloud secrets versions add oauth-gmail-test-client-secret --data-file="$HOME/credentials.json"

# If NOT project owner, add IAM binding to allow the user running the application access to the secret.
gcloud secrets add-iam-policy-binding oauth-gmail-test-client-secret \
  --role roles/secretmanager.secretAccessor \
  --member "user:your-email@example.com"

# other options:
# --member "serviceAccount:your-service-account@your-project.iam.gserviceaccount.com"
# --member "group:your-group-email@googlegroups.com"
```

## Run

Using a local oauth credentials file:

```
# Export oauth credentials file path
export CREDENTIALS_JSON_PATH="$HOME/credentials.json"

# export the email recipient
export EMAIL_TO="EMAIL@ADDRESS.COM"

# run the app (opens browser to log in, or add `--no-browser` to copy/paste)
go run main.go
```

Expected output:

```
Token is valid for: 59m58.999965875s
TokenType: Bearer
RefreshToken: nil
Expiry: 2023-11-14 11:13:20.427246 -0600 CST m=+3613.246309667
Access token contents:
{
    "access_type": "online",
    "aud": "some-string-of-numbers.apps.googleusercontent.com",
    "azp": "some-string-of-numbers.apps.googleusercontent.com",
    "exp": "1699982001",
    "expires_in": "3599",
    "scope": "https://www.googleapis.com/auth/gmail.send"
}

Test email sent!
```

If using Google Secret Manager for OAuth credentials:

```
unset CREDENTIALS_JSON_PATH
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project 2> /dev/null)
go run main.go
```

## Debug

The following error message appears generally when the `emailTo` field isn't updated in main.go.

```
Unable to send email googleapi: Error 400: Invalid To header, invalidArgument
exit status 1
```

The following error message appears when the user running `main.go` is not logged in via gcloud:

```
2023/11/13 12:09:27 Unable to read credentials from Secret Manager: failed to access secret version: rpc error: code = Unauthenticated desc = transport: per-RPC creds failed due to error: oauth2: "invalid_grant" "Token has been expired or revoked."
exit status 1
```

Fixed with: `gcloud auth application-default login`

## Test

```
# with local oauth creds file
gcloud auth revoke --all
export CREDENTIALS_JSON_PATH="$HOME/credentials.json"
go run main.go

# with GSM remote creds
unset CREDENTIALS_JSON_PATH
export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project 2> /dev/null)
go run main.go # should fail
gcloud auth application-default login
go run main.go # should pass

# w/o browser
go run main.go --no-browser
```

## Reference  

- https://cloud.google.com/docs/authentication/token-types#access
- OOB is deprecated: https://developers.google.com/identity/protocols/oauth2/resources/oob-migration#web-application
- Inspiration for no-browser: https://stackoverflow.com/a/71491500