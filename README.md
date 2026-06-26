# cli-qwen36plus-csharp

A small CLI tool that encrypts and decrypts using the rclone encryption defaults. 

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses: 
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 for the filenames.
- scrypt for keymaterial.

## Installation

**Homebrew (macOS/Linux)**

```bash
brew tap llm-supermarket/cli-qwen36plus-csharp https://github.com/llm-supermarket/cli-qwen36plus-csharp
brew install cli-qwen36plus-csharp
```

**Scoop (Windows)**

```bash
scoop bucket add cli-qwen36plus-csharp https://github.com/llm-supermarket/cli-qwen36plus-csharp
scoop install cli-qwen36plus-csharp
```

## Examples usage

### Basic encrypt/decrypt

```bash
# Encrypt a file (you will be prompted for a password)
cli-qwen36plus-csharp encrypt document.txt document.txt.encrypted

# Decrypt a file
cli-qwen36plus-csharp decrypt document.txt.encrypted document.txt
```

### With a custom salt

```bash
# Generate a salt (keep this if you want to decrypt later)
cli-qwen36plus-csharp generate-salt

# Encrypt with a custom salt
cli-qwen36plus-csharp encrypt --salt a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 input.txt output.bin

# Decrypt with the same salt
cli-qwen36plus-csharp decrypt --salt a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6 output.bin input.txt
```

### Supply password via environment variable (recommended)

```bash
export RCLONE_ENCRYPT_PASSWORD=mysecret
cli-qwen36plus-csharp encrypt input.txt output.bin
```

### Supply salt via environment variable

```bash
export RCLONE_ENCRYPT_SALT=deadbeefdeadbeefdeadbeefdeadbeef
cli-qwen36plus-csharp encrypt input.txt output.bin
cli-qwen36plus-csharp decrypt output.bin input.txt
```

### Automatic filename encryption (output optional)

When `-o`/`--output` is omitted, the filenames are automatically encrypted/decrypted using AES-EME (matching rclone):

```bash
# Encrypt: output filename is derived from the input filename
cli-qwen36plus-csharp encrypt document.txt

# Decrypt: original filename is recovered from the encrypted filename
cli-qwen36plus-csharp decrypt <encrypted-filename>

# -o/--output still works to override the derived name
cli-qwen36plus-csharp encrypt -i input.txt -o output.bin
```

### Supply password on command line (insecure)

**WARNING:** Using `--password` exposes the password in process listings and shell history. Consider using the `RCLONE_ENCRYPT_PASSWORD` environment variable or omitting the flag to be prompted securely.

```bash
cli-qwen36plus-csharp encrypt --password "mysecret" input.txt output.bin
```

### Custom filename encoding

```bash
# Use base64 encoding for encrypted filenames (default is base32)
cli-qwen36plus-csharp encrypt --filename-encoding base64 input.txt

# Decrypt with base64 encoding
cli-qwen36plus-csharp decrypt --filename-encoding base64 <encrypted-filename>
```

## Details

Rclone encryption uses:

- **NaCl SecretBox (XSalsa20 + Poly1305)** for file contents.
- **scrypt** (N=16384, r=8, p=1) for key derivation.
- **AES-EME** for filename encryption (32-byte key, 16-byte tweak).
- **Base32** encoding for encrypted filenames (lowercase, no padding) for case-insensitive FS compatibility.
- A **default salt** if none is provided (rclone-compatible).

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--password` | *(prompted)* | Encryption password (use env var `RCLONE_ENCRYPT_PASSWORD` instead when possible) |
| `--salt` | *(default rclone salt)* | Hex-encoded salt (omit to use rclone's default salt; also via `RCLONE_ENCRYPT_SALT` env var) |
| `-i`, `--input` | *(positional)* | Input file path |
| `-o`, `--output` | *(auto-derived)* | Output file path (omit to use AES-EME encrypted/decrypted filename) |
| `--filename-encoding` | `base32` | Filename encoding: base32 or base64 (also via `RCLONE_ENCRYPT_FILENAME_ENCODING` env var) |

## Building from Source

Requires .NET 10 SDK.

```bash
git clone https://github.com/llm-supermarket/cli-qwen36plus-csharp
cd cli-qwen36plus-csharp
dotnet build -c Release
```

### Running tests

```bash
dotnet test
```

## Releases

Pushing a `vX.Y.Z` tag triggers the [Build and Release workflow](.github/workflows/build-release.yml), which cross-compiles binaries for Linux and macOS (x64/arm64) and Windows (x64), publishes a GitHub Release, and updates the Scoop manifest (`cli-qwen36plus-csharp.json`) and Homebrew formula (`Formula/cli-qwen36plus-csharp.rb`) in this repo.
