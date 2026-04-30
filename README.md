# Mekarge Python Attestation Server RI

This is a reference implementation of a Python attestation server using Mekarge A3 as an Identity Provider. Attestation server uses a confidential client and is used in conjungtion with a native application to enhance security. The application validates **Access Tokens** and **Id Tokens** that are signed with `RS256` algorithm using discovery via OpenID Connect discovery (`.well-known/openid-configuration`).

The main idea behind reference implementations are to use widely adopted libraries instead of private libraries, thereby demonstrating the ease of adoption of Mekarge A3. Major dependencies are:

| Dependency                    | Library       |
| ----------------------------- | ------------- |
| Web Framework                 | `fastapi`     |
| OAuth2 Client                 | `authlib`     |
| Http Client (for discovery)   | `httpx`       |
| JOSE Tooling                  | `python-jose` |
| Google Auth                   | `google-auth` |

Supported Clients:
* Android

## Requirements

* Python 3.11+

## Installation

```bash
python -m venv .venv
```

Activate (macOS / Linux):

```bash
source .venv/bin/activate
```

Activate (Windows):

```bash
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Mekarge A3 Configuration

Ensure that the `Client` created in Mekarge A3 has:
* `Client Authentication Type` set to `Post (Http Body)`
* `PKCE` feature enabled
* `OpenID` feature enabled

### Application Configuration

Edit `.env` file to update following environment variables:

| Variable                      | Description   |
| ----------------------------- | ------------- |
| `ISSUER_PATH`                 | Issuer Path given for the target Environment |
| `CLIENT_ID`                   | Client Id |
| `CLIENT_SECRET`               | Client Secret |
| `VERIFIER_SECRET`             | Verifier Secret |
| `REDIRECT_URI`                | Redirection URL defined in Client |
| `RESOURCE_URI`                | Resource URI of the target Resource |
| `ATTESTATION_PROFILE_ANDROID` | Attestation Profile created for Android apps |
| `BASE URL`                    | Base URL accessible from the native app  |
| `DEEPLINK_URL`                | Deep link for redirecting to native app  |
| `ANDROID_PACKAGE_NAME`        | Package name of the target Android app  |
| `GOOGLE_SERVICE_ACCOUNT_FILE` | Account file to use Google APIs to validate Play Integrity token  |

### Running Server

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Development

Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

Formatting:

```bash
ruff format .
```

Linter:

```bash
ruff check .
```

Type Checker:

```bash
mypy .
```

### License

MIT

