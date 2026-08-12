# LockBox

A local password manager for the terminal, built with C# and .NET 8.

## Features

- AES-256 encryption with PBKDF2 key derivation (100k iterations)
- Master password authentication (SHA-256 hashed)
- Hidden password input (masked with `*`)
- Secure random password generator
- Search entries by name
- Single encrypted vault file

## Usage

```bash
dotnet run
```

On first run, you'll create a master password. After that, the menu gives you:

```
[1] List  [2] Add  [3] Get  [4] Delete  [5] Generate  [6] Exit
```

- **Add** — store a credential (or auto-generate a password)
- **Get** — search and reveal passwords
- **Generate** — create a strong random password

## Security

- Passwords are encrypted with AES-256-CBC
- Key derived via PBKDF2 with 100,000 iterations
- Vault file (`lockbox.vault`) is encrypted at rest
- No plaintext passwords stored on disk

## Tech

- C# / .NET 8
- System.Security.Cryptography (AES, PBKDF2, SHA-256)
- Console I/O with masked input
