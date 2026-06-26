using System.Security.Cryptography;
using System.Text;

namespace RcloneEncrypt;

public enum FilenameEncoding
{
    Base32,
    Base64
}

public static class FilenameCipher
{
    private const int BlockSize = 16;

    public static string EncryptFileName(string name, byte[] nameKey, byte[] nameTweak, FilenameEncoding encoding = FilenameEncoding.Base32)
    {
        if (string.IsNullOrEmpty(name))
            return name;

        var padded = Pkcs7Pad(name, BlockSize);
        var encrypted = EmeCipher.Encrypt(nameKey, nameTweak, padded);

        return encoding switch
        {
            FilenameEncoding.Base64 => Base64Encode(encrypted),
            _ => Base32Encode(encrypted)
        };
    }

    public static string DecryptFileName(string encryptedName, byte[] nameKey, byte[] nameTweak, FilenameEncoding encoding = FilenameEncoding.Base32)
    {
        if (string.IsNullOrEmpty(encryptedName))
            return encryptedName;

        var decoded = encoding switch
        {
            FilenameEncoding.Base64 => Base64Decode(encryptedName),
            _ => Base32Decode(encryptedName)
        };

        if (decoded.Length == 0 || decoded.Length % BlockSize != 0)
            throw new ArgumentException("Decrypted name is not a multiple of block size");

        var decrypted = EmeCipher.Decrypt(nameKey, nameTweak, decoded);
        return Pkcs7Unpad(decrypted);
    }

    public static string EncryptFilePath(string path, byte[] nameKey, byte[] nameTweak, FilenameEncoding encoding = FilenameEncoding.Base32)
    {
        var separator = path.Contains('\\') ? '\\' : '/';
        var segments = path.Split(separator);
        var encryptedSegments = segments.Select(s =>
            string.IsNullOrEmpty(s) ? s : EncryptFileName(s, nameKey, nameTweak, encoding)).ToArray();
        return string.Join(separator.ToString(), encryptedSegments);
    }

    public static string DecryptFilePath(string path, byte[] nameKey, byte[] nameTweak, FilenameEncoding encoding = FilenameEncoding.Base32)
    {
        var separator = path.Contains('\\') ? '\\' : '/';
        var segments = path.Split(separator);
        var decryptedSegments = segments.Select(s =>
            string.IsNullOrEmpty(s) ? s : DecryptFileName(s, nameKey, nameTweak, encoding)).ToArray();
        return string.Join(separator.ToString(), decryptedSegments);
    }

    private static byte[] Pkcs7Pad(string input, int blockSize)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var padding = blockSize - (bytes.Length % blockSize);
        var padded = new byte[bytes.Length + padding];
        Array.Copy(bytes, padded, bytes.Length);
        for (var i = bytes.Length; i < padded.Length; i++)
        {
            padded[i] = (byte)padding;
        }
        return padded;
    }

    private static string Pkcs7Unpad(byte[] padded)
    {
        if (padded.Length == 0)
            throw new ArgumentException("Invalid padding");

        var padding = padded[padded.Length - 1];
        if (padding == 0 || padding > padded.Length)
            throw new ArgumentException("Invalid padding");

        for (var i = padded.Length - padding; i < padded.Length; i++)
        {
            if (padded[i] != padding)
                throw new ArgumentException("Invalid padding");
        }

        return Encoding.UTF8.GetString(padded, 0, padded.Length - padding);
    }

    private static string Base32Encode(byte[] data)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;

            while (bitsLeft >= 5)
            {
                bitsLeft -= 5;
                result.Append(alphabet[(buffer >> bitsLeft) & 0x1F]);
            }
        }

        if (bitsLeft > 0)
        {
            result.Append(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
        }

        return result.ToString();
    }

    private static byte[] Base32Decode(string input)
    {
        var result = new List<byte>();
        int buffer = 0;
        int bitsLeft = 0;

        foreach (var c in input.ToLowerInvariant())
        {
            var val = c switch
            {
                >= 'a' and <= 'z' => c - 'a',
                >= '2' and <= '7' => c - '2' + 26,
                _ => throw new ArgumentException($"Invalid base32 character: {c}")
            };

            buffer = (buffer << 5) | val;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                bitsLeft -= 8;
                result.Add((byte)((buffer >> bitsLeft) & 0xFF));
            }
        }

        return [.. result];
    }

    private static string Base64Encode(byte[] data)
    {
        return Convert.ToBase64String(data)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }

    private static byte[] Base64Decode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        var padding = 4 - (padded.Length % 4);
        if (padding < 4)
        {
            padded += new string('=', padding);
        }
        return Convert.FromBase64String(padded);
    }
}
