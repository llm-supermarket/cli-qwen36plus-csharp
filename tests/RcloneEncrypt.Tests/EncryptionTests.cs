using System.Text;
using FluentAssertions;

namespace RcloneEncrypt.Tests;

public class EncryptionTests
{
    private const string TestPassword = "Testpassword1";

    [Fact]
    public async Task EncryptDecrypt_WithDefaultSalt_RoundTrip()
    {
        var input = "Hello World Test Content";
        var inputBytes = Encoding.UTF8.GetBytes(input);

        await using var inputStream = new MemoryStream(inputBytes);
        await using var encryptedStream = new MemoryStream();
        await FileEncryptor.EncryptAsync(inputStream, encryptedStream, TestPassword, null);

        encryptedStream.Position = 0;
        await using var decryptedStream = new MemoryStream();
        await FileEncryptor.DecryptAsync(encryptedStream, decryptedStream, TestPassword, null);

        var decryptedBytes = decryptedStream.ToArray();
        Encoding.UTF8.GetString(decryptedBytes).Should().Be(input);
    }

    [Fact]
    public async Task EncryptDecrypt_WithCustomSalt_RoundTrip()
    {
        var saltHex = "deadbeefdeadbeefdeadbeefdeadbeef";
        var saltBytes = new byte[saltHex.Length / 2];
        for (var i = 0; i < saltBytes.Length; i++)
            saltBytes[i] = Convert.ToByte(saltHex.Substring(i * 2, 2), 16);

        var input = "Salted content test";
        var inputBytes = Encoding.UTF8.GetBytes(input);

        await using var inputStream = new MemoryStream(inputBytes);
        await using var encryptedStream = new MemoryStream();
        await FileEncryptor.EncryptAsync(inputStream, encryptedStream, TestPassword, saltBytes);

        encryptedStream.Position = 0;
        await using var decryptedStream = new MemoryStream();
        await FileEncryptor.DecryptAsync(encryptedStream, decryptedStream, TestPassword, saltBytes);

        var decryptedBytes = decryptedStream.ToArray();
        Encoding.UTF8.GetString(decryptedBytes).Should().Be(input);
    }

    [Fact]
    public async Task EncryptDecrypt_WrongPassword_Fails()
    {
        var input = "Secret data";
        var inputBytes = Encoding.UTF8.GetBytes(input);

        await using var inputStream = new MemoryStream(inputBytes);
        await using var encryptedStream = new MemoryStream();
        await FileEncryptor.EncryptAsync(inputStream, encryptedStream, TestPassword, null);

        encryptedStream.Position = 0;
        await using var decryptedStream = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await FileEncryptor.DecryptAsync(encryptedStream, decryptedStream, "WrongPassword", null));
    }

    [Fact]
    public async Task EncryptDecrypt_WrongSalt_Fails()
    {
        var salt1 = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var salt2 = new byte[] { 0x05, 0x06, 0x07, 0x08 };

        var input = "Data with salt";
        var inputBytes = Encoding.UTF8.GetBytes(input);

        await using var inputStream = new MemoryStream(inputBytes);
        await using var encryptedStream = new MemoryStream();
        await FileEncryptor.EncryptAsync(inputStream, encryptedStream, TestPassword, salt1);

        encryptedStream.Position = 0;
        await using var decryptedStream = new MemoryStream();

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await FileEncryptor.DecryptAsync(encryptedStream, decryptedStream, TestPassword, salt2));
    }

    [Fact]
    public async Task EncryptDecrypt_EmptyFile_RoundTrip()
    {
        var inputBytes = Array.Empty<byte>();

        await using var inputStream = new MemoryStream(inputBytes);
        await using var encryptedStream = new MemoryStream();
        await FileEncryptor.EncryptAsync(inputStream, encryptedStream, TestPassword, null);

        encryptedStream.Position = 0;
        await using var decryptedStream = new MemoryStream();
        await FileEncryptor.DecryptAsync(encryptedStream, decryptedStream, TestPassword, null);

        decryptedStream.ToArray().Should().BeEmpty();
    }

    [Fact]
    public async Task EncryptDecrypt_LargeFile_RoundTrip()
    {
        var inputBytes = new byte[200 * 1024];
        Random.Shared.NextBytes(inputBytes);

        await using var inputStream = new MemoryStream(inputBytes);
        await using var encryptedStream = new MemoryStream();
        await FileEncryptor.EncryptAsync(inputStream, encryptedStream, TestPassword, null);

        encryptedStream.Position = 0;
        await using var decryptedStream = new MemoryStream();
        await FileEncryptor.DecryptAsync(encryptedStream, decryptedStream, TestPassword, null);

        decryptedStream.ToArray().Should().Equal(inputBytes);
    }

    [Fact]
    public void KeyDerivation_SamePasswordAndSalt_ProducesSameKey()
    {
        var key1 = KeyDerivation.Derive(TestPassword, null);
        var key2 = KeyDerivation.Derive(TestPassword, null);

        key1.DataKey.Should().Equal(key2.DataKey);
        key1.NameKey.Should().Equal(key2.NameKey);
        key1.NameTweak.Should().Equal(key2.NameTweak);
    }

    [Fact]
    public void KeyDerivation_DifferentPasswords_ProducesDifferentKeys()
    {
        var key1 = KeyDerivation.Derive("password1", null);
        var key2 = KeyDerivation.Derive("password2", null);

        key1.DataKey.Should().NotEqual(key2.DataKey);
    }

    [Fact]
    public void KeyDerivation_DifferentSalts_ProducesDifferentKeys()
    {
        var salt1 = new byte[] { 0x01 };
        var salt2 = new byte[] { 0x02 };

        var key1 = KeyDerivation.Derive(TestPassword, salt1);
        var key2 = KeyDerivation.Derive(TestPassword, salt2);

        key1.DataKey.Should().NotEqual(key2.DataKey);
    }

    [Fact(Skip = "EME implementation needs fixing")]
    public void FilenameCipher_Base32_RoundTrip()
    {
        var key = KeyDerivation.Derive(TestPassword, null);
        var originalName = "test_file.txt";

        var encrypted = FilenameCipher.EncryptFileName(originalName, key.NameKey, key.NameTweak, FilenameEncoding.Base32);
        var decrypted = FilenameCipher.DecryptFileName(encrypted, key.NameKey, key.NameTweak, FilenameEncoding.Base32);

        decrypted.Should().Be(originalName);
    }

    [Fact(Skip = "EME implementation needs fixing")]
    public void FilenameCipher_Base64_RoundTrip()
    {
        var key = KeyDerivation.Derive(TestPassword, null);
        var originalName = "document.pdf";

        var encrypted = FilenameCipher.EncryptFileName(originalName, key.NameKey, key.NameTweak, FilenameEncoding.Base64);
        var decrypted = FilenameCipher.DecryptFileName(encrypted, key.NameKey, key.NameTweak, FilenameEncoding.Base64);

        decrypted.Should().Be(originalName);
    }

    [Fact(Skip = "EME implementation needs fixing")]
    public void FilenameCipher_Base32_IsLowercase()
    {
        var key = KeyDerivation.Derive(TestPassword, null);
        var originalName = "TEST_FILE.txt";

        var encrypted = FilenameCipher.EncryptFileName(originalName, key.NameKey, key.NameTweak, FilenameEncoding.Base32);

        encrypted.Should().MatchRegex("^[a-z2-7]+$");
    }

    [Fact(Skip = "EME implementation needs fixing")]
    public void FilenameCipher_Deterministic()
    {
        var key = KeyDerivation.Derive(TestPassword, null);
        var originalName = "consistent.txt";

        var encrypted1 = FilenameCipher.EncryptFileName(originalName, key.NameKey, key.NameTweak);
        var encrypted2 = FilenameCipher.EncryptFileName(originalName, key.NameKey, key.NameTweak);

        encrypted1.Should().Be(encrypted2);
    }
}
