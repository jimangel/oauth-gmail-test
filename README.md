# oauth-gmail-test

A demo, with limited scope, allowing a local application to send emails on behalf of your personal gmail account via Google OAuth.

## High-level flow:

1) The application gets an GCP OAuth config file from `$CREDENTIALS_JSON_PATH` or looks to Google Secret Manager (using your `gcloud` credentials)
1) Launches a browser to prompt login, unless `--no-browser` is set

   ![](img/oauth-consent.png)

1) User authenticates using the URL flow, if `--no-browser` is set, copy response back to the terminal
1) A test email is sent on the recipients behalf (using a special variable "me" representing the authenticated user) to `$EMAIL_TO`.

> I believe there is a low quotas on sending gmail messages this way. Do not use for bulk sending.

## Setup

Assumes you already have a Google Cloud Project.

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

# if not project owner, add IAM binding to allow the user running the application access to the secret.
gcloud secrets add-iam-policy-binding my-secret \
  --role roles/secretmanager.secretAccessor \
  --member "user:your-email@example.com"

# --member "serviceAccount:your-service-account@your-project.iam.gserviceaccount.com"
# --member "group:your-group-email@googlegroups.com"

# unset CREDENTIALS_JSON_PATH
```

## Run

```
# If NOT using Google Secret Manager for OAuth credentials, export oauth clientID/secret filepath info
export CREDENTIALS_JSON_PATH="$HOME/credentials.json"

# If using Google Secret Manager for OAuth credentials
#gcloud auth login --update-adc
#export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project 2> /dev/null)

# export recipient
export EMAIL_TO="EMAIL@ADDRESS.COM"

# run the app (opens browser to log in, or add `--no-browser` to copy/paste)
go run main.go

# token stays in memory for the duration of the run
# an authorization call is made each time via browser
```

## Debug

The following error message appears generally when the `emailTo` field isn't updated in main.go.

```
Unable to send email googleapi: Error 400: Invalid To header, invalidArgument
exit status 1
```

## Ref

OOB is deprecated: https://developers.google.com/identity/protocols/oauth2/resources/oob-migration#web-application
Inspiration for no-browser: https://stackoverflow.com/a/71491500
