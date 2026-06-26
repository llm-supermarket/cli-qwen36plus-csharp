namespace RcloneEncrypt;

public static class Poly1305
{
    public const int MacSize = 16;
    public const int KeySize = 32;

    public static byte[] ComputeMac(byte[] message, byte[] key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException("Key must be 32 bytes");

        // Load r from key[0..15] with overlapping reads (NaCl style)
        var r0 = Load4(key, 0);
        var r1 = Load4(key, 3);
        var r2 = Load4(key, 6);
        var r3 = Load4(key, 9);
        var r4 = Load4(key, 12);

        // Clamp r
        r1 &= 0x0fffffff;
        r2 &= 0x0fffffff;
        r3 &= 0x0fffffff;
        r4 &= 0x0fffffff;

        var s1 = r1 * 5;
        var s2 = r2 * 5;
        var s3 = r3 * 5;
        var s4 = r4 * 5;

        ulong h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

        for (var i = 0; i < message.Length; i += 16)
        {
            var len = Math.Min(16, message.Length - i);

            ulong t0, t1, t2, t3;
            if (len >= 4) t0 = Load4(message, i); else t0 = LoadPartial(message, i, len);
            if (len >= 8) t1 = Load4(message, i + 4); else if (len > 4) t1 = LoadPartial(message, i + 4, len - 4); else t1 = 0;
            if (len >= 12) t2 = Load4(message, i + 8); else if (len > 8) t2 = LoadPartial(message, i + 8, len - 8); else t2 = 0;
            if (len >= 16) t3 = Load4(message, i + 12); else if (len > 12) t3 = LoadPartial(message, i + 12, len - 12); else t3 = 0;

            h0 += t0 & 0x0FFFFFFF;
            h1 += ((t0 >> 26) | (t1 << 6)) & 0x0FFFFFFF;
            h2 += ((t1 >> 20) | (t2 << 12)) & 0x0FFFFFFF;
            h3 += ((t2 >> 14) | (t3 << 18)) & 0x0FFFFFFF;
            h4 += (t3 >> 8) | ((ulong)1 << (len * 8 - 32));

            var d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
            var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
            var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
            var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

            var c = d0 >> 26; h0 = d0 & 0x3FFFFFF;
            d1 += c; c = d1 >> 26; h1 = d1 & 0x3FFFFFF;
            d2 += c; c = d2 >> 26; h2 = d2 & 0x3FFFFFF;
            d3 += c; c = d3 >> 26; h3 = d3 & 0x3FFFFFF;
            d4 += c; c = d4 >> 26; h4 = d4 & 0x3FFFFFF;
            h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3FFFFFF;
            h1 += c;
        }

        var g0 = h0 + 5; var c0 = g0 >> 26; g0 &= 0x3FFFFFF;
        var g1 = h1 + c0; var c1 = g1 >> 26; g1 &= 0x3FFFFFF;
        var g2 = h2 + c1; var c2 = g2 >> 26; g2 &= 0x3FFFFFF;
        var g3 = h3 + c2; var c3 = g3 >> 26; g3 &= 0x3FFFFFF;
        var g4 = h4 + c3 - (1UL << 26);

        var mask = (ulong)(-(long)(g4 >> 48));
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;

        g0 |= h0; g1 |= h1; g2 |= h2; g3 |= h3; g4 |= h4;

        // Load s from key[16..31]
        var f0 = g0 + Load4(key, 16);
        var f1 = g1 + Load4(key, 20) + (f0 >> 26); f0 &= 0x3FFFFFF;
        var f2 = g2 + Load4(key, 24) + (f1 >> 26); f1 &= 0x3FFFFFF;
        var f3 = g3 + Load4(key, 28) + (f2 >> 26); f2 &= 0x3FFFFFF;

        var mac = new byte[16];
        Store4(mac, 0, (uint)(f0 | (f1 << 26)));
        Store4(mac, 4, (uint)((f1 >> 6) | (f2 << 20)));
        Store4(mac, 8, (uint)((f2 >> 12) | (f3 << 14)));
        Store4(mac, 12, (uint)(f3 >> 18));
        return mac;
    }

    private static uint Load4(byte[] data, int offset)
    {
        return (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
    }

    private static ulong LoadPartial(byte[] data, int offset, int len)
    {
        ulong result = 0;
        for (var i = 0; i < len; i++)
        {
            result |= (ulong)data[offset + i] << (i * 8);
        }
        return result;
    }

    private static void Store4(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)value;
        data[offset + 1] = (byte)(value >> 8);
        data[offset + 2] = (byte)(value >> 16);
        data[offset + 3] = (byte)(value >> 24);
    }
}
