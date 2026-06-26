#### 1.0.0 June 26th 2026 ####

- Initial release with rclone-compatible encryption/decryption
- XSalsa20-Poly1305 for file contents
- scrypt (N=16384, r=8, p=1) for key derivation
- AES-EME for filename encryption
- Base32 and Base64 filename encoding support
- Cross-platform binaries via .NET 10 self-contained publishing
- Scoop and Homebrew package manager support
