using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;

namespace UnitySecurityScanner
{
    public class GameScanner
    {
        public class ScanResult
        {
            public string GameName { get; set; }
            public string AssemblyPath { get; set; }
            public List<SecurityScanner.SecurityIssue> Issues { get; set; }
        }

        private static readonly HashSet<string> IgnoredAssemblyPrefixes = new HashSet<string>
        {
            // Unity-related assemblies
            "UnityEngine",
            "Unity.",
            "TextMeshPro",
            "DOTween",
            "Cinemachine",
            "Mirror.",
            "Mirror-",
            "NavMeshComponents",
            "Photon",
            "PlayFab",
            "Steamworks",
            "FMOD",
            "AmplifyShader",
            "Rewired",
            "PostProcessing",
            "ProBuilder",

            // System and Microsoft assemblies
            "System.",
            "Microsoft.",
            "mscorlib",
            "netstandard",
            "WindowsBase",
            "Accessibility",

            // Common .NET and development libraries
            "Newtonsoft",
            "nunit.",
            "NUnit.",
            "Mono.",
            "ExCSS",
            "ICSharpCode.",
            "JetBrains.",
            "log4net",
            "Serilog",
            "NLog",

            // Cryptography and security libraries
            "BouncyCastle",
            "org.bouncycastle",
            "Nethereum",
            "NBitcoin",
            "SHA3",
            "HashLib",

            // Database and data libraries
            "SQLite",
            "MySql.",
            "MongoDB.",
            "EntityFramework",
            "Npgsql",
            "Dapper",
            "LiteDB",

            // Network and web libraries
            "WebSocket",
            "RestSharp",
            "Fleck",
            "SignalR",
            "Socket.IO",
            "websocket-sharp",

            // Common Unity asset store plugins
            "Coffee",
            "Demigiant",
            "DemiLib",
            "Sirenix",
            "Odin",
            "FullSerializer",
            "JsonDotNet",
            "LitJson",
            "UniRx",
            "UniTask",
            "AsyncAwaitUtil",
            "RTLTMPro",

            // AI and pathfinding
            "AstarPathfinding",
            "NavMesh",
            "MLAgents",

            // Common middleware and utilities
            "ZString",
            "MessagePack",
            "protobuf-net",
            "SimpleJSON",
            "I18N",
            "MiniJson",
            "SharpZipLib",
            "Ionic.Zip",
            "DotNetZip",
            
            // Analytics and crash reporting
            "Firebase",
            "GoogleAnalytics",
            "Crashlytics",
            "BugSplat",
            "Sentry",
            
            // Input systems
            "InputSystem",
            "InControl",
            "XInput",

            // VR/AR related
            "Oculus",
            "Steam.VR",
            "Vuforia",
            "OpenVR",
            "WindowsMR",
            
            // Testing frameworks
            "xunit",
            "MSTest",
            "FluentAssertions",
            "Moq",
            
            // Common optimization libraries
            "MemoryPack",
            "K4os",
            "Collections.Pooled",
            
            // UI frameworks
            "UGUI",
            "NoesisGUI",
            "UIElements",

            // Misc
            "ACTk",
            "Febucci",
            "zxing",
            "nethereum",
            "PimDeWitte",
            "Elringus",
            "StompyRobot",
            "Whinarn",
            "BestHTTP",
            "Facebook",
            "Google",
            "LibFBGManaged",
            "Mesh",
            "AYellowpaper",
            "NativeGallery",
            "Purchasing",
            "io",
            "Epic"


        };

        private static bool ShouldScanAssembly(string assemblyPath, string gameName)
        {
            var fileName = Path.GetFileName(assemblyPath);

            // Always scan the main game assemblies
            if (fileName == "Assembly-CSharp.dll" ||
                fileName == "Assembly-CSharp-firstpass.dll")
                return true;

            // Check for game-specific assemblies (case-insensitive)
            if (!string.IsNullOrEmpty(gameName) &&
                fileName.StartsWith(gameName, StringComparison.OrdinalIgnoreCase))
                return true;

            // Skip known system and Unity assemblies
            foreach (var prefix in IgnoredAssemblyPrefixes)
            {
                if (fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return false;
            }

            // For any other DLL, we'll scan it as it might be a custom game assembly
            return true;
        }

        public static ScanResult ScanGame(string gamePath)
        {
            try
            {
                // Find _Data directory
                var dataDirs = Directory.GetDirectories(gamePath, "*_Data");
                string managedPath = null;

                if (dataDirs.Any())
                {
                    managedPath = Path.Combine(dataDirs.First(), "Managed");
                }

                // Try Mac structure if Windows structure not found
                if (managedPath == null || !Directory.Exists(managedPath))
                {
                    var macDataPath = Path.Combine(gamePath, "Contents", "Resources", "Data");
                    managedPath = Path.Combine(macDataPath, "Managed");
                }

                if (!Directory.Exists(managedPath))
                {
                    throw new DirectoryNotFoundException($"Could not find Managed directory at {managedPath}");
                }

                var gameName = Path.GetFileName(gamePath);
                var allIssues = new List<SecurityScanner.SecurityIssue>();
                var scannedAssemblies = new List<string>();

                // Get all DLL files
                var assemblies = Directory.GetFiles(managedPath, "*.dll");

                Console.WriteLine("\nScanning game assemblies:");
                foreach (var assemblyPath in assemblies)
                {
                    if (ShouldScanAssembly(assemblyPath, gameName))
                    {
                        try
                        {
                            Console.WriteLine($"- Scanning: {Path.GetFileName(assemblyPath)}");
                            var scanner = new SecurityScanner(assemblyPath);
                            var issues = scanner.ScanForVulnerabilities();
                            allIssues.AddRange(issues);
                            scannedAssemblies.Add(assemblyPath);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"  Error scanning {Path.GetFileName(assemblyPath)}: {ex.Message}");
                        }
                    }
                }

                if (!scannedAssemblies.Any())
                {
                    throw new FileNotFoundException("No valid game assemblies found to scan");
                }

                return new ScanResult
                {
                    GameName = gameName,
                    AssemblyPath = string.Join(", ", scannedAssemblies.Select(Path.GetFileName)),
                    Issues = allIssues
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error scanning game: {ex.Message}");
                throw;
            }
        }

        public static bool IsUnityGame(string path)
        {
            if (!Directory.Exists(path))
                return false;

            try
            {
                // Get all directories that end with _Data
                var dataDirs = Directory.GetDirectories(path, "*_Data");

                foreach (var dataDir in dataDirs)
                {
                    var managedPath = Path.Combine(dataDir, "Managed");
                    if (Directory.Exists(managedPath))
                    {
                        // Look for key Unity assemblies
                        var hasUnityEngine = Directory.GetFiles(managedPath, "UnityEngine*.dll").Any();
                        var hasAssemblyCSharp = Directory.GetFiles(managedPath, "Assembly-CSharp*.dll").Any();

                        if (hasUnityEngine && hasAssemblyCSharp)
                        {
                            return true;
                        }
                    }
                }

                // Also check Mac structure
                var macDataPath = Path.Combine(path, "Contents", "Resources", "Data");
                if (Directory.Exists(macDataPath))
                {
                    var macManagedPath = Path.Combine(macDataPath, "Managed");
                    if (Directory.Exists(macManagedPath))
                    {
                        return Directory.GetFiles(macManagedPath, "UnityEngine*.dll").Any() &&
                               Directory.GetFiles(macManagedPath, "Assembly-CSharp*.dll").Any();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking if Unity game: {ex.Message}");
            }

            return false;
        }

        public static string FindMainAssembly(string gamePath)
        {
            try
            {
                var dataPath = Path.Combine(gamePath, $"{Path.GetFileName(gamePath)}_Data");
                var managedPath = Path.Combine(dataPath, "Managed");

                if (!Directory.Exists(managedPath))
                {
                    // Try Mac structure
                    dataPath = Path.Combine(gamePath, "Contents", "Resources", "Data");
                    managedPath = Path.Combine(dataPath, "Managed");
                }

                if (!Directory.Exists(managedPath))
                {
                    throw new DirectoryNotFoundException($"Could not find Managed directory in {gamePath}");
                }

                var assemblyPath = Directory.GetFiles(managedPath, "Assembly-CSharp.dll").FirstOrDefault();
                if (assemblyPath == null)
                {
                    throw new FileNotFoundException("Could not find Assembly-CSharp.dll");
                }

                return assemblyPath;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error finding main assembly: {ex.Message}", ex);
            }
        }

        public static string[] FindAllAssemblies(string gamePath)
        {
            try
            {
                // Find _Data directory
                var dataDirs = Directory.GetDirectories(gamePath, "*_Data");
                string managedPath = null;

                if (dataDirs.Any())
                {
                    managedPath = Path.Combine(dataDirs.First(), "Managed");
                }

                // Try Mac structure if Windows structure not found
                if (managedPath == null || !Directory.Exists(managedPath))
                {
                    var macDataPath = Path.Combine(gamePath, "Contents", "Resources", "Data");
                    managedPath = Path.Combine(macDataPath, "Managed");
                }

                if (!Directory.Exists(managedPath))
                {
                    throw new DirectoryNotFoundException($"Could not find Managed directory");
                }

                var gameName = Path.GetFileName(gamePath);
                return Directory.GetFiles(managedPath, "*.dll")
                    .Where(dll => ShouldScanAssembly(dll, gameName))
                    .ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error finding assemblies: {ex.Message}");
                throw;
            }
        }
    }
}