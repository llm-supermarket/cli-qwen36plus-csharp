using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography;

namespace RcloneEncrypt;

public static class Program
{
    private const string Version = "1.0.0";

    public static async Task<int> Main(string[] args)
    {
        var passwordOption = new Option<string?>(
            ["--password"],
            "Password (WARNING: insecure on command line - use env var RCLONE_ENCRYPT_PASSWORD instead)");

        var saltOption = new Option<string?>(
            ["--salt"],
            "Optional hex-encoded salt (omit to use rclone's default salt)");

        var inputArgument = new Argument<string?>("input", "Input file path");
        var outputArgument = new Argument<string?>("output", "Output file path (optional)");
        outputArgument.SetDefaultValue(null);

        var encodingOption = new Option<string?>(
            ["--filename-encoding"],
            "Filename encoding: base32 (default) or base64");

        var encryptCommand = new Command("encrypt", "Encrypt a file")
        {
            passwordOption, saltOption, inputArgument, outputArgument, encodingOption
        };
        encryptCommand.SetHandler(async ctx =>
        {
            var password = ctx.ParseResult.GetValueForOption(passwordOption);
            var saltHex = ctx.ParseResult.GetValueForOption(saltOption);
            var input = ctx.ParseResult.GetValueForArgument(inputArgument);
            var output = ctx.ParseResult.GetValueForArgument(outputArgument);
            var encodingStr = ctx.ParseResult.GetValueForOption(encodingOption);

            ctx.ExitCode = await RunEncrypt(password, saltHex, input, output, encodingStr);
        });

        var decryptCommand = new Command("decrypt", "Decrypt a file")
        {
            passwordOption, saltOption, inputArgument, outputArgument, encodingOption
        };
        decryptCommand.SetHandler(async ctx =>
        {
            var password = ctx.ParseResult.GetValueForOption(passwordOption);
            var saltHex = ctx.ParseResult.GetValueForOption(saltOption);
            var input = ctx.ParseResult.GetValueForArgument(inputArgument);
            var output = ctx.ParseResult.GetValueForArgument(outputArgument);
            var encodingStr = ctx.ParseResult.GetValueForOption(encodingOption);

            ctx.ExitCode = await RunDecrypt(password, saltHex, input, output, encodingStr);
        });

        var generateSaltCommand = new Command("generate-salt", "Generate a random 16-byte salt (hex-encoded)");
        generateSaltCommand.SetHandler(ctx =>
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);
            Console.WriteLine(BitConverter.ToString(salt).Replace("-", "").ToLowerInvariant());
            ctx.ExitCode = 0;
        });

        var versionCommand = new Command("version", "Print version");
        versionCommand.SetHandler(ctx =>
        {
            Console.WriteLine($"rclone-encrypt {Version}");
            ctx.ExitCode = 0;
        });

        var rootCommand = new RootCommand("Encrypts and decrypts files using rclone-compatible encryption (XSalsa20-Poly1305 + scrypt).");
        rootCommand.AddCommand(encryptCommand);
        rootCommand.AddCommand(decryptCommand);
        rootCommand.AddCommand(generateSaltCommand);
        rootCommand.AddCommand(versionCommand);

        return await rootCommand.InvokeAsync(args);
    }

    private static async Task<int> RunEncrypt(string? password, string? saltHex, string? input, string? output, string? encodingStr)
    {
        if (string.IsNullOrEmpty(input))
        {
            Console.Error.WriteLine("error: input file is required");
            return 1;
        }

        password = ResolvePassword(password);
        var salt = ResolveSalt(saltHex);
        var encoding = ResolveEncoding(encodingStr);

        if (string.IsNullOrEmpty(output))
        {
            var dirPrefix = Path.GetDirectoryName(input) ?? "";
            var fileSegment = Path.GetFileName(input);
            var key = KeyDerivation.Derive(password, salt);
            var derived = FilenameCipher.EncryptFileName(fileSegment, key.NameKey, key.NameTweak, encoding);
            output = Path.Combine(dirPrefix, derived);
            Console.Error.WriteLine($"Derived output filename: {output}");
        }

        Console.Error.WriteLine($"Encrypting {input} -> {output} ...");

        try
        {
            await using var inputStream = File.OpenRead(input);
            await using var outputStream = File.Create(output);
            await FileEncryptor.EncryptAsync(inputStream, outputStream, password, salt);
            Console.Error.WriteLine("Done.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            Console.Error.WriteLine($"stack: {ex.StackTrace}");
            return 1;
        }
    }

    private static async Task<int> RunDecrypt(string? password, string? saltHex, string? input, string? output, string? encodingStr)
    {
        if (string.IsNullOrEmpty(input))
        {
            Console.Error.WriteLine("error: input file is required");
            return 1;
        }

        password = ResolvePassword(password);
        var salt = ResolveSalt(saltHex);
        var encoding = ResolveEncoding(encodingStr);

        if (string.IsNullOrEmpty(output))
        {
            var dirPrefix = Path.GetDirectoryName(input) ?? "";
            var fileSegment = Path.GetFileName(input);
            var key = KeyDerivation.Derive(password, salt);
            var derived = FilenameCipher.DecryptFileName(fileSegment, key.NameKey, key.NameTweak, encoding);
            output = Path.Combine(dirPrefix, derived);
            Console.Error.WriteLine($"Derived output filename: {output}");
        }

        Console.Error.WriteLine($"Decrypting {input} -> {output} ...");

        try
        {
            await using var inputStream = File.OpenRead(input);
            await using var outputStream = File.Create(output);
            await FileEncryptor.DecryptAsync(inputStream, outputStream, password, salt);
            Console.Error.WriteLine("Done.");
            return 0;
        }
        catch (InvalidDataException ex) when (ex.Message.Contains("magic"))
        {
            Console.Error.WriteLine("error: not an rclone-encrypted file (bad magic)");
            return 1;
        }
        catch (InvalidDataException ex) when (ex.Message.Contains("password") || ex.Message.Contains("corrupt"))
        {
            Console.Error.WriteLine("error: wrong password or corrupt data");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static string ResolvePassword(string? fromFlag)
    {
        if (!string.IsNullOrEmpty(fromFlag))
        {
            Console.Error.WriteLine("WARNING: Using --password on the command line is insecure.");
            Console.Error.WriteLine("         The password is visible in process listings and shell history.");
            Console.Error.WriteLine("         Use RCLONE_ENCRYPT_PASSWORD environment variable instead,");
            Console.Error.WriteLine("         or omit --password to be prompted securely.");
            Console.Error.WriteLine("         If you must use --password, wipe your terminal history afterwards.");
            return fromFlag;
        }

        var envPw = Environment.GetEnvironmentVariable("RCLONE_ENCRYPT_PASSWORD");
        if (!string.IsNullOrEmpty(envPw))
            return envPw;

        Console.Error.Write("Password: ");
        var pw = ReadPassword();
        Console.Error.WriteLine();

        if (string.IsNullOrEmpty(pw))
            throw new InvalidOperationException("Password cannot be empty");

        return pw;
    }

    private static string ReadPassword()
    {
        var password = new System.Text.StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
                break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Length--;
                    Console.Error.Write("\b \b");
                }
            }
            else
            {
                password.Append(key.KeyChar);
                Console.Error.Write("*");
            }
        }
        return password.ToString();
    }

    private static byte[]? ResolveSalt(string? hexSalt)
    {
        hexSalt ??= Environment.GetEnvironmentVariable("RCLONE_ENCRYPT_SALT");
        if (string.IsNullOrEmpty(hexSalt))
            return null;

        try
        {
            hexSalt = hexSalt.Trim();
            var bytes = new byte[hexSalt.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexSalt.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        catch
        {
            throw new InvalidOperationException("Invalid salt hex");
        }
    }

    private static FilenameEncoding ResolveEncoding(string? fromFlag)
    {
        fromFlag ??= Environment.GetEnvironmentVariable("RCLONE_ENCRYPT_FILENAME_ENCODING");
        if (string.IsNullOrEmpty(fromFlag))
            return FilenameEncoding.Base32;

        return fromFlag.ToLowerInvariant() switch
        {
            "base32" => FilenameEncoding.Base32,
            "base64" => FilenameEncoding.Base64,
            _ => throw new InvalidOperationException($"Unknown filename encoding: {fromFlag} (supported: base32, base64)")
        };
    }
}
