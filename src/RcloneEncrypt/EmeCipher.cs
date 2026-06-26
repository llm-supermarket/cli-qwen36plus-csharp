using System.Security.Cryptography;

namespace RcloneEncrypt;

public static class EmeCipher
{
    private const int BlockSize = 16;

    public static byte[] Encrypt(byte[] key, byte[] tweak, byte[] plaintext)
    {
        if (plaintext.Length == 0)
            return plaintext;

        if (plaintext.Length % BlockSize != 0)
            throw new ArgumentException("Plaintext must be a multiple of block size");

        var m = plaintext.Length / BlockSize;
        var blocks = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            blocks[i] = new byte[BlockSize];
            Array.Copy(plaintext, i * BlockSize, blocks[i], 0, BlockSize);
        }

        var pp = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            pp[i] = AesEcbEncrypt(key, blocks[i]);
        }

        var tau = ComputeTau(tweak, pp);
        var l = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            var doubledTau = GfMult(tau, i == 0 ? 1 : 1UL << (i - 1));
            l[i] = XorBlocks(pp[i], doubledTau);
        }

        var cc = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            cc[i] = AesEcbEncrypt(key, l[i]);
        }

        var crc = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            var doubledTau = GfMult(tau, i == 0 ? 1 : 1UL << (i - 1));
            crc[i] = XorBlocks(cc[i], doubledTau);
        }

        var ciphertext = new byte[plaintext.Length];
        for (var i = 0; i < m; i++)
        {
            Array.Copy(crc[i], 0, ciphertext, i * BlockSize, BlockSize);
        }
        return ciphertext;
    }

    public static byte[] Decrypt(byte[] key, byte[] tweak, byte[] ciphertext)
    {
        if (ciphertext.Length == 0)
            return ciphertext;

        if (ciphertext.Length % BlockSize != 0)
            throw new ArgumentException("Ciphertext must be a multiple of block size");

        var m = ciphertext.Length / BlockSize;
        var blocks = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            blocks[i] = new byte[BlockSize];
            Array.Copy(ciphertext, i * BlockSize, blocks[i], 0, BlockSize);
        }

        var tau = ComputeTau(tweak, blocks);
        var cc = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            var doubledTau = GfMult(tau, i == 0 ? 1 : 1UL << (i - 1));
            cc[i] = XorBlocks(blocks[i], doubledTau);
        }

        var l = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            l[i] = AesEcbDecrypt(key, cc[i]);
        }

        var pp = new byte[m][];
        for (var i = 0; i < m; i++)
        {
            var doubledTau = GfMult(tau, i == 0 ? 1 : 1UL << (i - 1));
            pp[i] = XorBlocks(l[i], doubledTau);
        }

        var plaintext = new byte[ciphertext.Length];
        for (var i = 0; i < m; i++)
        {
            Array.Copy(pp[i], 0, plaintext, i * BlockSize, BlockSize);
        }
        return plaintext;
    }

    private static byte[] AesEcbEncrypt(byte[] key, byte[] block)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var encryptor = aes.CreateEncryptor();
        return encryptor.TransformFinalBlock(block, 0, block.Length);
    }

    private static byte[] AesEcbDecrypt(byte[] key, byte[] block)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(block, 0, block.Length);
    }

    private static byte[] ComputeTau(byte[] tweak, byte[][] blocks)
    {
        var sum = new byte[BlockSize];
        foreach (var block in blocks)
        {
            for (var i = 0; i < BlockSize; i++)
            {
                sum[i] ^= block[i];
            }
        }

        var h = new HMACSHA256(tweak);
        var hash = h.ComputeHash(sum);
        var tau = new byte[BlockSize];
        Array.Copy(hash, 0, tau, 0, BlockSize);
        return tau;
    }

    private static byte[] GfMult(byte[] a, ulong b)
    {
        var result = new byte[BlockSize];
        var temp = (byte[])a.Clone();

        for (var bit = 0; bit < 64; bit++)
        {
            if ((b & (1UL << bit)) != 0)
            {
                for (var i = 0; i < BlockSize; i++)
                {
                    result[i] ^= temp[i];
                }
            }

            var carry = (temp[0] & 0x80) != 0;
            for (var i = 0; i < BlockSize - 1; i++)
            {
                temp[i] = (byte)((temp[i] << 1) | (temp[i + 1] >> 7));
            }
            temp[BlockSize - 1] = (byte)(temp[BlockSize - 1] << 1);
            if (carry)
            {
                temp[BlockSize - 1] ^= 0x87;
            }
        }

        return result;
    }

    private static byte[] XorBlocks(byte[] a, byte[] b)
    {
        var result = new byte[BlockSize];
        for (var i = 0; i < BlockSize; i++)
        {
            result[i] = (byte)(a[i] ^ b[i]);
        }
        return result;
    }
}
