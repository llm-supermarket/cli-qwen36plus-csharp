using System.Security.Cryptography;

namespace RcloneEncrypt;

public static class FileEncryptor
{
    public static async Task EncryptAsync(Stream input, Stream output, string password, byte[]? salt, CancellationToken ct = default)
    {
        var key = KeyDerivation.Derive(password, salt);
        var nonce = new byte[SecretBox.NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var header = new byte[RcloneCipher.FileHeaderSize];
        var magicBytes = System.Text.Encoding.UTF8.GetBytes(RcloneCipher.FileMagic);
        Array.Copy(magicBytes, header, RcloneCipher.FileMagicSize);
        Array.Copy(nonce, 0, header, RcloneCipher.FileMagicSize, SecretBox.NonceSize);

        await output.WriteAsync(header, ct);

        var buffer = new byte[RcloneCipher.BlockDataSize];

        while (true)
        {
            var bytesRead = await ReadUpToAsync(input, buffer, ct);
            if (bytesRead == 0)
                break;

            var encrypted = SecretBox.Seal(buffer[..bytesRead], nonce, key.DataKey);
            await output.WriteAsync(encrypted, ct);

            IncrementNonce(nonce);
        }
    }

    public static async Task DecryptAsync(Stream input, Stream output, string password, byte[]? salt, CancellationToken ct = default)
    {
        var key = KeyDerivation.Derive(password, salt);

        var header = new byte[RcloneCipher.FileHeaderSize];
        var headerRead = await ReadUpToAsync(input, header, ct);
        if (headerRead < RcloneCipher.FileHeaderSize)
            throw new InvalidDataException("File too short");

        var magic = System.Text.Encoding.UTF8.GetString(header, 0, RcloneCipher.FileMagicSize);
        if (magic != RcloneCipher.FileMagic)
            throw new InvalidDataException("Bad magic bytes");

        var nonce = new byte[SecretBox.NonceSize];
        Array.Copy(header, RcloneCipher.FileMagicSize, nonce, 0, SecretBox.NonceSize);

        var tagBuffer = new byte[SecretBox.MacSize];
        var dataBuffer = new byte[RcloneCipher.BlockDataSize + SecretBox.MacSize];

        while (true)
        {
            var tagRead = await ReadUpToAsync(input, tagBuffer, ct);
            if (tagRead == 0)
                break;
            if (tagRead < SecretBox.MacSize)
                throw new InvalidDataException("Truncated auth tag");

            var dataRead = 0;
            while (dataRead < RcloneCipher.BlockDataSize)
            {
                var n = await input.ReadAsync(dataBuffer.AsMemory(SecretBox.MacSize + dataRead, RcloneCipher.BlockDataSize - dataRead), ct);
                if (n == 0)
                    break;
                dataRead += n;
            }

            var blockLen = SecretBox.MacSize + dataRead;
            Array.Copy(tagBuffer, 0, dataBuffer, 0, SecretBox.MacSize);
            var decrypted = SecretBox.Open(dataBuffer[..blockLen], nonce, key.DataKey);
            if (decrypted == null)
                throw new InvalidDataException("Wrong password or corrupt data");

            await output.WriteAsync(decrypted, ct);
            IncrementNonce(nonce);

            if (dataRead < RcloneCipher.BlockDataSize)
                break;
        }
    }

    private static async Task<int> ReadUpToAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), ct);
            if (read == 0)
                return totalRead;
            totalRead += read;
        }
        return totalRead;
    }

    private static void IncrementNonce(byte[] nonce)
    {
        for (var i = 0; i < nonce.Length; i++)
        {
            nonce[i]++;
            if (nonce[i] != 0)
                break;
        }
    }
}
