namespace RcloneEncrypt;

public static class RcloneCipher
{
    public const string FileMagic = "RCLONE\x00\x00";
    public const int FileMagicSize = 8;
    public const int FileNonceSize = 24;
    public const int FileHeaderSize = 32;
    public const int BlockHeaderSize = 16;
    public const int BlockDataSize = 64 * 1024;
    public const int BlockSize = BlockHeaderSize + BlockDataSize;
    public const int ScryptN = 16384;
    public const int ScryptR = 8;
    public const int ScryptP = 1;
    public const int ScryptKeyLen = 80;

    public static readonly byte[] DefaultSalt =
    [
        0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
        0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1
    ];
}
