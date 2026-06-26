using System.Security.Cryptography;
using System.Text;

namespace RcloneEncrypt;

public sealed record RcloneKey(byte[] DataKey, byte[] NameKey, byte[] NameTweak)
{
    public byte[] DataKey { get; init; } = DataKey;
    public byte[] NameKey { get; init; } = NameKey;
    public byte[] NameTweak { get; init; } = NameTweak;
}

public static class KeyDerivation
{
    public static RcloneKey Derive(string password, byte[]? salt = null)
    {
        salt ??= RcloneCipher.DefaultSalt;

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var keyBytes = ScryptImpl.ComputeKey(passwordBytes, salt,
            RcloneCipher.ScryptN, RcloneCipher.ScryptR, RcloneCipher.ScryptP, RcloneCipher.ScryptKeyLen);

        var dataKey = new byte[32];
        var nameKey = new byte[32];
        var nameTweak = new byte[16];

        Array.Copy(keyBytes, 0, dataKey, 0, 32);
        Array.Copy(keyBytes, 32, nameKey, 0, 32);
        Array.Copy(keyBytes, 64, nameTweak, 0, 16);

        return new RcloneKey(dataKey, nameKey, nameTweak);
    }

    private static class ScryptImpl
    {
        public static byte[] ComputeKey(byte[] password, byte[] salt, int n, int r, int p, int derivedKeyLength)
        {
            var b = new byte[128 * r * p];
            PBKDF2(password, salt, 1, b);

            var blockSize = 128 * r;
            var v = new byte[blockSize * n];
            var xy = new byte[blockSize];

            for (var i = 0; i < p; i++)
            {
                ROMix(b, i * blockSize, v, xy, n, r);
            }

            var output = new byte[derivedKeyLength];
            PBKDF2(password, b, 1, output);
            return output;
        }

        private static void PBKDF2(byte[] password, byte[] salt, int iterations, byte[] output)
        {
            using var hmac = new HMACSHA256(password);
            var blockIndex = 1;
            var offset = 0;

            while (offset < output.Length)
            {
                var saltBlock = new byte[salt.Length + 4];
                Array.Copy(salt, saltBlock, salt.Length);
                saltBlock[salt.Length] = (byte)(blockIndex >> 24);
                saltBlock[salt.Length + 1] = (byte)(blockIndex >> 16);
                saltBlock[salt.Length + 2] = (byte)(blockIndex >> 8);
                saltBlock[salt.Length + 3] = (byte)blockIndex;

                var u = hmac.ComputeHash(saltBlock);
                var t = (byte[])u.Clone();

                for (var j = 1; j < iterations; j++)
                {
                    u = hmac.ComputeHash(u);
                    for (var k = 0; k < t.Length; k++)
                    {
                        t[k] ^= u[k];
                    }
                }

                var copyLen = Math.Min(t.Length, output.Length - offset);
                Array.Copy(t, 0, output, offset, copyLen);
                offset += copyLen;
                blockIndex++;
            }
        }

        private static void ROMix(byte[] b, int bOffset, byte[] v, byte[] xy, int n, int r)
        {
            var blockLen = 128 * r;
            var x = new byte[blockLen];
            Array.Copy(b, bOffset, x, 0, blockLen);

            for (var i = 0; i < n; i++)
            {
                Array.Copy(x, 0, v, i * blockLen, blockLen);
                BlockMix(x, xy, r);
            }

            for (var i = 0; i < n; i++)
            {
                var j = Integerify(x, r) & (n - 1);
                XorBlock(v, j * blockLen, x, 0, blockLen);
                BlockMix(x, xy, r);
            }

            Array.Copy(x, 0, b, bOffset, blockLen);
        }

        private static void BlockMix(byte[] b, byte[] xy, int r)
        {
            var x = new byte[64];
            Array.Copy(b, (2 * r - 1) * 64, x, 0, 64);

            for (var i = 0; i < 2 * r; i++)
            {
                XorBlock(x, 0, b, i * 64, 64);
                Salsa20Core8(x, 0, xy, i * 64);
                Array.Copy(xy, i * 64, x, 0, 64);
            }

            for (var i = 0; i < r; i++)
            {
                Array.Copy(xy, i * 2 * 64, b, i * 64, 64);
            }
            for (var i = 0; i < r; i++)
            {
                Array.Copy(xy, (i * 2 + 1) * 64, b, (r + i) * 64, 64);
            }
        }

        private static void Salsa20Core8(byte[] input, int inputOffset, byte[] output, int outputOffset)
        {
            var x = new uint[16];
            for (var i = 0; i < 16; i++)
            {
                x[i] = BitConverter.ToUInt32(input, inputOffset + i * 4);
            }

            var y = (uint[])x.Clone();

            for (var i = 0; i < 4; i++)
            {
                QuarterRound(ref y[0], ref y[4], ref y[8], ref y[12]);
                QuarterRound(ref y[5], ref y[9], ref y[13], ref y[1]);
                QuarterRound(ref y[10], ref y[14], ref y[2], ref y[6]);
                QuarterRound(ref y[15], ref y[3], ref y[7], ref y[11]);

                QuarterRound(ref y[0], ref y[1], ref y[2], ref y[3]);
                QuarterRound(ref y[5], ref y[6], ref y[7], ref y[4]);
                QuarterRound(ref y[10], ref y[11], ref y[8], ref y[9]);
                QuarterRound(ref y[15], ref y[12], ref y[13], ref y[14]);
            }

            for (var i = 0; i < 16; i++)
            {
                BitConverter.TryWriteBytes(output.AsSpan(outputOffset + i * 4), x[i] + y[i]);
            }
        }

        private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            b ^= RotateLeft(a + d, 7);
            c ^= RotateLeft(b + a, 9);
            d ^= RotateLeft(c + b, 13);
            a ^= RotateLeft(d + c, 18);
        }

        private static uint RotateLeft(uint value, int shift) => (value << shift) | (value >> (32 - shift));

        private static int Integerify(byte[] b, int r)
        {
            var offset = (2 * r - 1) * 64;
            return (int)BitConverter.ToUInt32(b, offset);
        }

        private static void XorBlock(byte[] a, int aOffset, byte[] b, int bOffset, int length)
        {
            for (var i = 0; i < length; i++)
            {
                a[aOffset + i] ^= b[bOffset + i];
            }
        }
    }
}
