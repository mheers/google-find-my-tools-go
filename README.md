# google-find-my-tools-go

A Go (re)implementation of the cryptographic and API client parts of
[GoogleFindMyTools](https://github.com/cyberomb/GoogleFindMyTools) — a set of tools
to interact with Google's Find My Device Network (now the **Find Hub** network).

This library lets you:

- Derive and verify **EID** / **FMDN** tracker identifiers
- Encrypt and decrypt **location reports** exchanged with the Find Hub network
- Work with **key backup** blobs, **foreign tracker** sharing, and **owner keys**
- Talk to the **Nova** and **Spot** APIs, and to Google's **FCM** (push) and
  **gRPC** endpoints
- Perform the **OAuth** browser flow needed to obtain a session token

> [!CAUTION]
> This is experimental software. Use it only with devices and accounts you own.
> The Find Hub network is a live service; automating interaction with it may
> violate Google's terms of service.

## Installation

```sh
go get github.com/mheers/google-find-my-tools-go
```

The library requires Go 1.26 or newer.

## Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/crypto"
)

func main() {
    // identityKey is the 32-byte EIK recovered from the account's key backup.
    identityKey := make([]byte, 32)
    eid, err := crypto.GenerateEID(identityKey, 1_700_000_000)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("EID: %x\n", eid)
}
```

The public API is split into focused packages under `pkg/googlefindmy`:

| Package            | Responsibility                                                        |
| ------------------ | --------------------------------------------------------------------- |
| `auth`             | GPSOAuth token derivation and token storage                           |
| `browser`          | Chrome-driven OAuth and shared-key flows                              |
| `chrome`           | Shared Chrome launch configuration for the automation flows           |
| `crypto`           | EID/FMDN, EAX, location encryption, key backup, secp160r1 primitives  |
| `fcm`              | FCM check-in, registration and push (MCS) client                      |
| `grpc`             | Minimal gRPC framing used by the Spot API                             |
| `httpclient`       | Default HTTP client (30s timeout) shared by the API clients           |
| `maps`             | Geocoding / Maps Location Sharing helpers                             |
| `maps/savedplaces` | Google Maps saved-lists client and discovery                          |
| `nova`             | Nova API client                                                       |
| `spot`             | Spot API client and owner-key handling                                |
| `proto/fcm`        | Generated protobuf types for FCM                                      |
| `proto/findhub`    | Generated protobuf types for the Find Hub backend                     |

## Logging

The library uses `log/slog`. Lifecycle messages are emitted at `Info`,
protocol chatter and payload metadata at `Debug`, and recoverable problems at
`Warn`. Credentials, key material and decrypted payloads are never logged. To
see the protocol details while debugging:

```go
slog.SetLogLoggerLevel(slog.LevelDebug)
```

Sentinel errors (`auth.ErrSecretsNotFound`, `maps.ErrCookiesExpired`,
`browser.ErrTimeout`) can be tested with `errors.Is`.

## Interactive sign-in flows

`browser.RunOAuthFlow`, `browser.RequestSharedKey` and `maps.AuthenticateMaps`
open a visible Chrome window. They drive Chrome through chromedp, which by
default launches a throwaway profile and flags the browser as automated; Google
refuses sign-in from such a browser with *"This browser or app may not be
secure"*. The launch configuration therefore disables the automation flag and
supports a persistent profile:

```go
cfg := chrome.Config{
    UserDataDir: "/path/to/chrome-profile", // reuse a signed-in profile
}
_, err := browser.RunOAuthFlow(ctx, cfg, "")
if err != nil {
    log.Fatal(err)
}
```

Sign the profile in **once**, outside the automation, then close it:

```sh
google-chrome --user-data-dir=/path/to/chrome-profile
```

Every later run reuses the session and never visits the sign-in page. Without a
`UserDataDir`, each run gets a fresh temporary profile and must sign in again —
which Google increasingly blocks. The launcher also keeps Chrome's normal
password store: chromedp's `--password-store=basic` and `--use-mock-keychain`
defaults change the cookie encryption key, which would make the primed
profile's cookies unreadable and silently sign the account out.

The `RunOAuthFlow` URL is
`accounts.google.com/EmbeddedSetup`, the same entry point the Python
implementation uses; it needs no OAuth client ID (the hardcoded client of the
earlier Go port has been retired by Google).

## Secrets handling

Credentials are kept in a single JSON file (commonly `secrets.json`) containing
Google session cookies (`SID`, `HSID`, `SAPISID`), OAuth/AAS tokens, the FCM
private key with its android id, and the E2EE shared/owner keys.

Treat this file like a password: the session cookies alone grant full access to
the account's Find Hub data.

- `auth.NewStore` creates the parent directory with `0700` and `Save` writes the
  file atomically with `0600` permissions.
- Never commit it. This repository's `.gitignore` excludes `secrets.json`,
  `**/secrets.json`, `*.secrets.json` and `.env`.
- Keep the file outside the repository and back it up only in encrypted form.
- If it leaks: sign the session out (Google Account → Security → Your devices),
  delete the file and re-run the authentication flow.

## Development

Regenerating the protobuf code requires [`buf`](https://buf.build):

```sh
cd internal/googlefindmy/proto
buf generate
```

Run the tests with:

```sh
go test ./...
```

## License

Copyright © 2024 Leon Böttger — original Python implementation
([GoogleFindMyTools](https://github.com/cyberomb/GoogleFindMyTools)).

Copyright © 2026 Marcel Heers &lt;marcel@heers.it&gt; — Go port.

Handwritten source files carry an SPDX license identifier; generated files
under `pkg/googlefindmy/proto` keep the header emitted by the protobuf
generator.

This program is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License, version 3** (GPL-3.0) as published by the
Free Software Foundation. The original Python library is also distributed under
GPL-3.0, and this derivative work is licensed accordingly.

You should have received a copy of the GNU General Public License along with this
program. If not, see <https://www.gnu.org/licenses/>.

The full license text is available in the [`LICENSE`](./LICENSE) file.
