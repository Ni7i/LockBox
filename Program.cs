using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string VaultFile = "lockbox.vault";

if (!File.Exists(VaultFile))
{
    Console.Write("Create master password: ");
    var master = ReadPassword();
    Console.Write("Confirm: ");
    var confirm = ReadPassword();

    if (master != confirm)
    {
        Console.WriteLine("Passwords don't match.");
        return;
    }

    var vault = new Vault(DeriveHash(master), []);
    SaveVault(vault, master);
    Console.WriteLine("Vault created.\n");
}

Console.Write("Master password: ");
var password = ReadPassword();
var loaded = LoadVault(password);

if (loaded is null)
{
    Console.WriteLine("Wrong password.");
    return;
}

Console.WriteLine($"Vault unlocked. {loaded.Entries.Count} entries.\n");

while (true)
{
    Console.WriteLine("[1] List  [2] Add  [3] Get  [4] Delete  [5] Generate  [6] Exit");
    Console.Write("> ");
    var choice = Console.ReadLine()?.Trim();

    switch (choice)
    {
        case "1":
            if (loaded.Entries.Count == 0)
            {
                Console.WriteLine("No entries.\n");
                break;
            }
            for (var i = 0; i < loaded.Entries.Count; i++)
                Console.WriteLine($"  [{i}] {loaded.Entries[i].Name} ({loaded.Entries[i].Username})");
            Console.WriteLine();
            break;

        case "2":
            Console.Write("Name: ");
            var name = Console.ReadLine()?.Trim() ?? "";
            Console.Write("Username: ");
            var user = Console.ReadLine()?.Trim() ?? "";
            Console.Write("Password (empty to generate): ");
            var pw = ReadPassword();
            if (string.IsNullOrEmpty(pw))
            {
                pw = GeneratePassword(20);
                Console.WriteLine($"Generated: {pw}");
            }
            loaded.Entries.Add(new Entry(name, user, pw));
            SaveVault(loaded, password);
            Console.WriteLine("Saved.\n");
            break;

        case "3":
            Console.Write("Search: ");
            var query = Console.ReadLine()?.Trim() ?? "";
            var matches = loaded.Entries.Where(e =>
                e.Name.Contains(query, StringComparison.OrdinalIgnoreCase)).ToList();
            if (matches.Count == 0)
            {
                Console.WriteLine("Not found.\n");
                break;
            }
            foreach (var m in matches)
            {
                Console.WriteLine($"  {m.Name}");
                Console.WriteLine($"  User: {m.Username}");
                Console.WriteLine($"  Pass: {m.Password}\n");
            }
            break;

        case "4":
            Console.Write("Name to delete: ");
            var del = Console.ReadLine()?.Trim() ?? "";
            var removed = loaded.Entries.RemoveAll(e =>
                e.Name.Equals(del, StringComparison.OrdinalIgnoreCase));
            if (removed > 0)
            {
                SaveVault(loaded, password);
                Console.WriteLine("Deleted.\n");
            }
            else Console.WriteLine("Not found.\n");
            break;

        case "5":
            Console.Write("Length (default 20): ");
            var lenStr = Console.ReadLine()?.Trim();
            var len = int.TryParse(lenStr, out var l) ? l : 20;
            Console.WriteLine($"  {GeneratePassword(len)}\n");
            break;

        case "6":
            Console.WriteLine("Locked.");
            return;

        default:
            Console.WriteLine("Invalid option.\n");
            break;
    }
}

static string ReadPassword()
{
    var sb = new StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
        {
            sb.Remove(sb.Length - 1, 1);
            Console.Write("\b \b");
        }
        else if (key.Key != ConsoleKey.Backspace)
        {
            sb.Append(key.KeyChar);
            Console.Write('*');
        }
    }
    Console.WriteLine();
    return sb.ToString();
}

static string DeriveHash(string input)
{
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
    return Convert.ToBase64String(bytes);
}

static byte[] DeriveKey(string password)
{
    var salt = Encoding.UTF8.GetBytes("LockBox-Salt-v1");
    return Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
}

static void SaveVault(Vault vault, string masterPassword)
{
    var json = JsonSerializer.Serialize(vault.Entries);
    var plainBytes = Encoding.UTF8.GetBytes(json);

    using var aes = Aes.Create();
    aes.Key = DeriveKey(masterPassword);
    aes.GenerateIV();

    using var ms = new MemoryStream();
    ms.Write(aes.IV);
    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
        cs.Write(plainBytes);

    var package = new VaultFile(vault.MasterHash, Convert.ToBase64String(ms.ToArray()));
    File.WriteAllText(VaultFile, JsonSerializer.Serialize(package, new JsonSerializerOptions { WriteIndented = true }));
}

static Vault? LoadVault(string masterPassword)
{
    var fileJson = File.ReadAllText(VaultFile);
    var vaultFile = JsonSerializer.Deserialize<VaultFile>(fileJson);
    if (vaultFile is null) return null;

    if (DeriveHash(masterPassword) != vaultFile.MasterHash)
        return null;

    var cipherBytes = Convert.FromBase64String(vaultFile.EncryptedData);

    using var aes = Aes.Create();
    aes.Key = DeriveKey(masterPassword);
    aes.IV = cipherBytes[..16];

    using var ms = new MemoryStream(cipherBytes[16..]);
    using var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
    using var reader = new StreamReader(cs);
    var json = reader.ReadToEnd();

    var entries = JsonSerializer.Deserialize<List<Entry>>(json) ?? [];
    return new Vault(vaultFile.MasterHash, entries);
}

static string GeneratePassword(int length)
{
    const string chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
    var result = new char[length];
    for (var i = 0; i < length; i++)
        result[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];
    return new string(result);
}

record Entry(string Name, string Username, string Password);
record Vault(string MasterHash, List<Entry> Entries);
record VaultFile(string MasterHash, string EncryptedData);
