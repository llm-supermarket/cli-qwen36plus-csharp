using Chaos.NaCl;

namespace RcloneEncrypt;

public static class SecretBox
{
    public const int NonceSize = 24;
    public const int MacSize = 16;

    public static byte[] Seal(byte[] message, byte[] nonce, byte[] key)
    {
        return XSalsa20Poly1305.Encrypt(message, key, nonce);
    }

    public static byte[]? Open(byte[] ciphertext, byte[] nonce, byte[] key)
    {
        if (ciphertext.Length < MacSize)
            return null;

        return XSalsa20Poly1305.TryDecrypt(ciphertext, key, nonce);
    }
}
