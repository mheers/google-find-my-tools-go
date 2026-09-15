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
import (
    "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/crypto"
    "github.com/mheers/google-find-my-tools-go/pkg/googlefindmy/nova"
)

// ... use the packages as needed
```

The public API is split into focused packages under
`internal/googlefindmy`:

| Package            | Responsibility                                                        |
| ------------------ | --------------------------------------------------------------------- |
| `auth`             | GPSOAuth token derivation and token storage                           |
| `browser`          | Chrome-driven OAuth login flow                                        |
| `crypto`           | EID/FMDN, EAX, location encryption, key backup, secp160r1 primitives  |
| `fcm`              | FCM check-in and push registration                                    |
| `grpc`             | gRPC client for the Find Hub backend                                  |
| `maps`             | Geocoding / maps helpers                                              |
| `nova`             | Nova API client                                                       |
| `spot`             | Spot API client and owner-key handling                                |
| `proto/fcm`        | Generated protobuf types for FCM                                      |
| `proto/findhub`    | Generated protobuf types for the Find Hub backend                     |

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

This program is free software: you can redistribute it and/or modify it under the
terms of the **GNU General Public License, version 3** (GPL-3.0) as published by the
Free Software Foundation. The original Python library is also distributed under
GPL-3.0, and this derivative work is licensed accordingly.

You should have received a copy of the GNU General Public License along with this
program. If not, see <https://www.gnu.org/licenses/>.

The full license text is available in the [`LICENSE`](./LICENSE) file.
