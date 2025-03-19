using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.TypeSystem;
using System.Text.RegularExpressions;

namespace UnitySecurityScanner
{
    public class SecurityScanner
    {
        private readonly string _assemblyPath;
        private readonly CSharpDecompiler _decompiler;
        private readonly ScannerConfig _config;

        public SecurityScanner(string assemblyPath, ScannerConfig config = null)
        {
            _assemblyPath = assemblyPath;
            _config = config ?? new ScannerConfig();

            var settings = new DecompilerSettings()
            {
                ThrowOnAssemblyResolveErrors = false,
                RemoveDeadCode = false,
                ShowXmlDocumentation = true
            };
            _decompiler = new CSharpDecompiler(assemblyPath, settings);
        }



        public class ScannerConfig
        {
            public bool ScanForUnsafeSerialization { get; set; } = true;
            public bool ScanForUnsafeCode { get; set; } = true;
            public bool ScanForInsecureFileOps { get; set; } = true;
            public bool ScanForInsecureNetworking { get; set; } = true;
            public bool ScanForHardcodedSecrets { get; set; } = true;
            public bool EnableDeepScan { get; set; } = false;
            public int MaxConcurrentScans { get; set; } = 4;
            public HashSet<string> IgnoredVulnerabilities { get; set; } = new HashSet<string>();
        }

        public class SecurityIssue
        {
            public string IssueType { get; set; }
            public string Location { get; set; }
            public string Description { get; set; }
            public string Severity { get; set; }
            public string Recommendation { get; set; }
            public string FoundValue { get; set; }
            public string Context { get; set; }
            public int LineNumber { get; set; }
            public double CvssScore { get; set; }
            public double FalsePositiveConfidence { get; set; }
            public string CvssVector { get; set; }
            public Dictionary<string, string> AdditionalInfo { get; set; }
        }

        public List<SecurityIssue> ScanForVulnerabilities()
        {
            var issues = new List<SecurityIssue>();
            var scannedNamespaces = new HashSet<string>();
            int totalTypes = 0;

            try
            {
                Console.WriteLine("\nStarting security scan...\n");
                var types = _decompiler.TypeSystem.MainModule.TypeDefinitions;

                // First pass - collect namespaces
                foreach (var type in types)
                {
                    if (!string.IsNullOrEmpty(type.Namespace))
                    {
                        scannedNamespaces.Add(type.Namespace);
                    }
                }

                // Log namespaces being scanned
                Console.WriteLine("Scanning Namespaces:");
                foreach (var ns in scannedNamespaces.OrderBy(n => n))
                {
                    Console.WriteLine($"- {ns}");
                }
                Console.WriteLine();

                // Second pass - scan types
                foreach (var type in types)
                {
                    try
                    {
                        totalTypes++;
                        string namespace_info = string.IsNullOrEmpty(type.Namespace) ? "(Global Namespace)" : type.Namespace;
                        string type_info = type.Name;

                        // Only log the type if it's directly in a namespace (not nested)
                        if (type.DeclaringType == null)
                        {
                            Console.WriteLine($"Scanning: {namespace_info}.{type_info}");
                        }

                        string decompiledCode = _decompiler.DecompileType(
                            new ICSharpCode.Decompiler.TypeSystem.FullTypeName(type.FullName)
                        ).ToString();

                        // Core security scans
                        if (_config.ScanForHardcodedSecrets)
                        {
                            ScanForApiKeys(decompiledCode, type.FullName, issues);
                            ScanForHardcodedCredentials(decompiledCode, type.FullName, issues);
                        }

                        if (_config.ScanForInsecureNetworking)
                        {
                            ScanForInsecureNetworkCalls(decompiledCode, type.FullName, issues);
                        }

                        // Enhanced security scans
                        if (_config.ScanForUnsafeSerialization)
                        {
                            ScanForInsecureSerialization(decompiledCode, type.FullName, issues);
                        }

                        if (_config.ScanForUnsafeCode)
                        {
                            ScanForUnsafeCodeUsage(decompiledCode, type.FullName, issues);
                        }

                        if (_config.ScanForInsecureFileOps)
                        {
                            ScanForInsecureFileOperations(decompiledCode, type.FullName, issues);
                        }

                        // Deep scan checks
                        if (_config.EnableDeepScan)
                        {
                            ScanForUnitySpecificIssues(decompiledCode, type.FullName, issues);
                            ScanForInputValidation(decompiledCode, type.FullName, issues);
                            ScanForInsecureRandomization(decompiledCode, type.FullName, issues);
                            ScanForCryptographicIssues(decompiledCode, type.FullName, issues);
                            ScanForInputValidationRisks(decompiledCode, type.FullName, issues);
                            ScanForEventInjectionRisks(decompiledCode, type.FullName, issues);
                            ScanForDataExposure(decompiledCode, type.FullName, issues);
                            ScanForAssetBundleSecurity(decompiledCode, type.FullName, issues);
                            ScanForWebGLVulnerabilities(decompiledCode, type.FullName, issues);
                        }
                    }
                    catch (Exception ex)
                    {
                        //Console.WriteLine($"[Error] Failed to scan {type.FullName}: {ex.Message}");
                    }
                }

                // Display the completion banner
                Console.WriteLine(@"
██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╔╝██║ ╚████║██║   ██║      ██║       ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
======================================================================
              [CREATED BY 0XRETRODEV]  [BUILD: 0.1.14] 
======================================================================");

                Console.WriteLine($"\nScan Summary:");
                Console.WriteLine($"- Namespaces Found: {scannedNamespaces.Count}");
                Console.WriteLine($"- Total Types Scanned: {totalTypes}");
                Console.WriteLine($"- Issues Found: {issues.Count}");

                if (_config.EnableDeepScan)
                {
                    Console.WriteLine("- Deep Scan: Enabled");
                }

                // Add severity breakdown
                var severityCounts = issues.GroupBy(i => i.Severity)
                                         .OrderByDescending(g => g.Key)
                                         .ToDictionary(g => g.Key, g => g.Count());

                if (severityCounts.Any())
                {
                    Console.WriteLine("\nIssues by Severity:");
                    foreach (var severity in severityCounts)
                    {
                        Console.WriteLine($"- {severity.Key}: {severity.Value}");
                    }
                }

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n[Critical Error] Error scanning assembly: {ex.Message}");
            }

            // Post-process issues
            foreach (var issue in issues)
            {
                issue.CvssScore = CalculateCvssScore(issue);
                issue.FalsePositiveConfidence = CalculateFalsePositiveConfidence(issue);
            }

            return issues;
        }

        private void ScanForUnsafeCodeUsage(string code, string typePath, List<SecurityIssue> issues)
        {
            var unsafePatterns = new Dictionary<string, (string type, string severity, string cvss)>
            {
                { @"unsafe\s*{", ("Unsafe Code Block", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
                { @"Marshal\.(Copy|AllocHGlobal|PtrToStructure)", ("Unsafe Memory Operations", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
                { @"fixed\s*\(", ("Fixed Memory Location", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L") },
                { @"stackalloc\s", ("Stack Allocation", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L") },
                { @"DllImport\s*\(", ("P/Invoke Usage", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L") }
            };

            foreach (var pattern in unsafePatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var context = GetExtendedContext(code, match.Index, 200);

                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = GetUnsafeCodeDescription(pattern.Value.type),
                        Severity = pattern.Value.severity,
                        Recommendation = GetUnsafeCodeRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = context,
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                        {
                            { "Category", "Memory Safety" },
                            { "Impact", "Potential memory corruption or code execution" }
                        }
                    });
                }
            }
        }

        private void ScanForInsecureFileOperations(string code, string typePath, List<SecurityIssue> issues)
        {
            var fileOpPatterns = new Dictionary<string, (string type, string severity, string cvss)>
            {
                { @"File\.(Open|Create|Delete|Move|Copy)\s*\([^)]*\)",
                    ("Unsafe File Operation", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
                { @"Directory\.(Create|Delete|Move|GetFiles)\s*\([^)]*\)",
                    ("Unsafe Directory Operation", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
                { @"Path\.Combine\s*\([^)]*\.\.[^)]*\)",
                    ("Path Traversal Risk", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
                { @"new FileStream\s*\([^)]+,\s*FileMode\.(Open|Create|Append)",
                    ("Unchecked FileStream Usage", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L") }
            };

            foreach (var pattern in fileOpPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var context = GetExtendedContext(code, match.Index, 200);

                    // Skip if proper security checks are present in context
                    if (HasSecurityChecks(context))
                        continue;

                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = GetFileOperationDescription(pattern.Value.type),
                        Severity = pattern.Value.severity,
                        Recommendation = GetFileOperationRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = context,
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                        {
                            { "Category", "File System Security" },
                            { "Impact", "Potential file system manipulation or information disclosure" }
                        }
                    });
                }
            }
        }

        private void ScanForCryptographicIssues(string code, string typePath, List<SecurityIssue> issues)
        {
            var cryptoPatterns = new Dictionary<string, (string type, string severity, string cvss)>
        {
            // Weak Cryptography
            { @"MD5\.(Create|ComputeHash)|new\s+MD5CryptoServiceProvider",
                ("Weak Hashing (MD5)", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") },
            { @"SHA1\.(Create|ComputeHash)|new\s+SHA1CryptoServiceProvider",
                ("Weak Hashing (SHA1)", "Medium", "AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:N/A:N") },
            
            // Insecure Random Numbers
            { @"new\s+Random\s*\(\s*\)",
                ("Insecure Random Generation", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N") },
            
            // Hardcoded Crypto Keys
            { @"(Key|IV|Salt)\s*=\s*new\s+byte\[\]\s*{\s*[0-9,\s]+\s*}",
                ("Hardcoded Cryptographic Material", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
            
            // Weak Encryption
            { @"DESCryptoServiceProvider|RC2CryptoServiceProvider",
                ("Obsolete Encryption Algorithm", "Critical", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
            
            // ECB Mode Usage
            { @"CipherMode\.ECB|Mode\s*=\s*CipherMode\.ECB",
                ("Insecure Cipher Mode (ECB)", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") }
        };

            foreach (var pattern in cryptoPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = GetCryptoIssueDescription(pattern.Value.type),
                        Severity = pattern.Value.severity,
                        Recommendation = GetCryptoRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssScore = CalculateCvssScore(pattern.Value.cvss),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                    {
                        { "Category", "Cryptographic Security" },
                        { "Impact", GetCryptoImpact(pattern.Value.type) }
                    }
                    });
                }
            }
        }

        private void ScanForInputValidationRisks(string code, string typePath, List<SecurityIssue> issues)
        {
            var inputPatterns = new Dictionary<string, (string type, string severity, string cvss)>
        {
            // File Path Traversal
            { @"Path\.Combine\s*\([^)]*\.\.[^)]*\)",
                ("Path Traversal Risk", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
            
            // SQL Injection
            { @"string\.Format\s*\([^)]*\bSQL\b[^)]*\)|ExecuteQuery\s*\([^)]*\+",
                ("SQL Injection Risk", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
            
            // Command Injection
            { @"Process\.Start\s*\([^)]*\+|cmd\.exe|/bin/bash",
                ("Command Injection Risk", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
            
            // Unvalidated Redirects
            { @"Response\.Redirect\s*\([^)]*\+|Application\.OpenURL\s*\([^)]*\+",
                ("Unvalidated Redirect", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N") },
            
            // XML External Entity
            { @"XmlDocument\.Load|XmlReader\.Create\s*\([^,)]*\)",
                ("XML External Entity Risk", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L") }
        };

            foreach (var pattern in inputPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = GetInputValidationDescription(pattern.Value.type),
                        Severity = pattern.Value.severity,
                        Recommendation = GetInputValidationRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssScore = CalculateCvssScore(pattern.Value.cvss),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                    {
                        { "Category", "Input Validation" },
                        { "Impact", GetInputValidationImpact(pattern.Value.type) }
                    }
                    });
                }
            }
        }

        private string GetCryptoIssueDescription(string issueType) => issueType switch
        {
            "Weak Hashing (MD5)" => "MD5 is cryptographically broken and unsuitable for further use",
            "Weak Hashing (SHA1)" => "SHA1 is cryptographically broken and unsuitable for security purposes",
            "Insecure Random Generation" => "Using non-cryptographic random number generator",
            "Hardcoded Cryptographic Material" => "Hardcoded cryptographic keys/IVs compromise security",
            "Obsolete Encryption Algorithm" => "Using deprecated encryption algorithm with known vulnerabilities",
            "Insecure Cipher Mode (ECB)" => "ECB mode does not provide semantic security",
            _ => "Potential cryptographic vulnerability detected"
        };

        private void ScanForUnitySpecificIssues(string code, string typePath, List<SecurityIssue> issues)
        {
            var unityPatterns = new Dictionary<string, (string type, string severity, string cvss)>
            {
                { @"OnValidate\s*\(\s*\)\s*{[^}]*(?:WWW|UnityWebRequest|File\.|PlayerPrefs)",
                    ("Unsafe OnValidate Usage", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
                { @"GameObject\.Find\s*\([^)]+\)",
                    ("Inefficient GameObject.Find", "Low", "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L") },
                { @"SendMessage\s*\([^)]+\)",
                    ("Unsafe SendMessage Usage", "Medium", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L") },
                { @"PlayerPrefs\.(Set|Get)[^(]*\([^)]*\)",
                    ("Unencrypted PlayerPrefs", "Medium", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N") }
            };

            foreach (var pattern in unityPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var context = GetExtendedContext(code, match.Index, 200);

                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = GetUnityIssueDescription(pattern.Value.type),
                        Severity = pattern.Value.severity,
                        Recommendation = GetUnityIssueRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = context,
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                        {
                            { "Category", "Unity-Specific Security" },
                            { "Impact", "Performance or security implications in Unity context" }
                        }
                    });
                }
            }
        }

        private bool HasSecurityChecks(string context)
        {
            var securityCheckPatterns = new[]
            {
                @"Path\.GetFullPath",
                @"Directory\.Exists",
                @"File\.Exists",
                @"try\s*{.*?}\s*catch",
                @"if\s*\([^)]*(?:Path|File|Directory)[^)]*\)"
            };

            return securityCheckPatterns.Any(pattern =>
                Regex.IsMatch(context, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline));
        }

        // Add these patterns to your SecurityScanner class

        private void ScanForEventInjectionRisks(string code, string typePath, List<SecurityIssue> issues)
        {
            var eventPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"SendMessage(Upwards)?\s*\([^)]*\)",
            ("Unity SendMessage Injection Risk", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
        { @"BroadcastMessage\s*\([^)]*\)",
            ("Unity BroadcastMessage Injection Risk", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
        { @"Invoke\s*\([^)]*\)",
            ("Unity Invoke Injection Risk", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:M/I:M/A:L") },
        { @"InvokeRepeating\s*\([^)]*\)",
            ("Unity InvokeRepeating Injection Risk", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:M/I:M/A:L") }
    };

            foreach (var pattern in eventPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = "Dynamic method invocation that could be exploited for code injection",
                        Severity = pattern.Value.severity,
                        Recommendation = "Use direct method calls or a type-safe event system instead of string-based method invocation",
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                {
                    { "Category", "Code Injection" },
                    { "Impact", "Potential remote code execution" }
                }
                    });
                }
            }
        }

        private void ScanForDataExposure(string code, string typePath, List<SecurityIssue> issues)
        {
            var exposurePatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"Debug\.(Log|LogWarning|LogError)\s*\([^)]*(?:password|token|key|secret|credential)[^)]*\)",
            ("Sensitive Data Logging", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") },
        { @"WWWForm\.AddField\s*\([^)]*(?:password|token|key|secret|credential)[^)]*\)",
            ("Sensitive Data in Form", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") },
        { @"url\s*\+\s*(?:password|token|key|secret|credential)",
            ("Sensitive Data in URL", "Critical", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N") },
        { @"Application\.persistentDataPath\s*\+.*(?:password|token|key|secret|credential)",
            ("Sensitive Data in Persistent Storage", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") }
    };

            foreach (var pattern in exposurePatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = "Potential exposure of sensitive data through logs or storage",
                        Severity = pattern.Value.severity,
                        Recommendation = "Avoid logging or storing sensitive data. Use secure storage solutions for necessary sensitive data.",
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                {
                    { "Category", "Data Exposure" },
                    { "Impact", "Potential exposure of sensitive information" }
                }
                    });
                }
            }
        }

        private void ScanForAssetBundleSecurity(string code, string typePath, List<SecurityIssue> issues)
        {
            var assetBundlePatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"AssetBundle\.LoadFromFile\s*\([^)]*\)",
            ("Unverified Asset Bundle Loading", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
        { @"WWW\s*\(\s*[""']https?://[^""']+\.(?:assetbundle|unity3d)[""']\s*\)",
            ("Remote Asset Bundle Loading", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
        { @"AssetBundle\.LoadFromMemory(?:Async)?\s*\([^)]*\)",
            ("Unverified Memory Asset Loading", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") }
    };

            foreach (var pattern in assetBundlePatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = "Loading asset bundles without proper verification could lead to code execution",
                        Severity = pattern.Value.severity,
                        Recommendation = "Implement signature verification for asset bundles and only load from trusted sources",
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                {
                    { "Category", "Asset Security" },
                    { "Impact", "Potential arbitrary code execution through malicious assets" }
                }
                    });
                }
            }
        }

        private void ScanForWebGLVulnerabilities(string code, string typePath, List<SecurityIssue> issues)
        {
            var webGLPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"Application\.ExternalEval\s*\([^)]*\)",
            ("WebGL JavaScript Injection", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
        { @"Application\.ExternalCall\s*\([^)]*\)",
            ("Unvalidated External Call", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
        { @"jslib\s*=\s*[""'][^""']*eval\s*\([^""']*[""']",
            ("JavaScript Eval in Plugin", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") }
    };

            foreach (var pattern in webGLPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = "Potential WebGL-specific security vulnerability",
                        Severity = pattern.Value.severity,
                        Recommendation = "Avoid using eval() and validate all external JavaScript calls",
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss,
                        AdditionalInfo = new Dictionary<string, string>
                {
                    { "Category", "WebGL Security" },
                    { "Impact", "Potential JavaScript injection in WebGL builds" }
                }
                    });
                }
            }
        }

        private void ScanForInsecureSerialization(string code, string typePath, List<SecurityIssue> issues)
        {
            var serializationPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"BinaryFormatter\s*\.", ("Insecure BinaryFormatter Usage", "Critical", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
        { @"JavaScriptSerializer\s*\.", ("Legacy JavaScript Serializer", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L") },
        { @"XmlSerializer\s*\([^)]*\)", ("Unconfigured XML Serializer", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L") },
        { @"JsonSerializerSettings\s*\{[^}]*TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto)",
          ("Unsafe JSON Deserialization", "Critical", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") }
    };

            foreach (var pattern in serializationPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var context = GetExtendedContext(code, match.Index, 200);

                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = $"Potentially unsafe serialization detected using {pattern.Value.type}",
                        Severity = pattern.Value.severity,
                        Recommendation = GetSerializationRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = context,
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss
                    });
                }
            }
        }

        private void ScanForInputValidation(string code, string typePath, List<SecurityIssue> issues)
        {
            var inputValidationPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"Input\.GetString\s*\([^)]*\)", ("Unvalidated Input", "Medium", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L") },
        { @"PlayerPrefs\.GetString\s*\([^)]*\)", ("Unvalidated PlayerPrefs", "Medium", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L") },
        { @"Convert\.ToInt32\s*\([^)]*\)", ("Unchecked Number Conversion", "Low", "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L") },
        { @"Parse\s*\([^)]*\)", ("Unchecked Parsing", "Low", "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L") }
    };

            foreach (var pattern in inputValidationPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    if (!HasInputValidation(GetExtendedContext(code, match.Index, 200)))
                    {
                        issues.Add(new SecurityIssue
                        {
                            IssueType = pattern.Value.type,
                            Location = typePath,
                            Description = "Missing input validation for user-provided data",
                            Severity = pattern.Value.severity,
                            Recommendation = GetInputValidationRecommendation(pattern.Value.type),
                            FoundValue = match.Value,
                            Context = GetExtendedContext(code, match.Index, 200),
                            LineNumber = GetLineNumber(code, match.Index),
                            CvssVector = pattern.Value.cvss
                        });
                    }
                }
            }
        }

        private void ScanForInsecureRandomization(string code, string typePath, List<SecurityIssue> issues)
        {
            var randomizationPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        { @"Random\s*\.\s*Next", ("Weak Random Number Generator", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N") },
        { @"UnityEngine\.Random\.Range", ("Predictable Game Random", "Low", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N") },
        { @"new\s+Random\s*\(\s*\)", ("Unseeded Random", "Medium", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N") }
    };

            foreach (var pattern in randomizationPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,
                        Description = "Potentially insecure randomization method detected",
                        Severity = pattern.Value.severity,
                        Recommendation = GetRandomizationRecommendation(pattern.Value.type),
                        FoundValue = match.Value,
                        Context = GetExtendedContext(code, match.Index, 200),
                        LineNumber = GetLineNumber(code, match.Index),
                        CvssVector = pattern.Value.cvss
                    });
                }
            }
        }

        private string GetUnsafeCodeDescription(string issueType)
        {
            return issueType switch
            {
                "Unsafe Code Block" => "Usage of unsafe code block which bypasses .NET type safety and memory management",
                "Unsafe Memory Operations" => "Direct memory manipulation which could lead to memory corruption or buffer overflows",
                "Fixed Memory Location" => "Usage of fixed statement which pins memory location and could cause memory fragmentation",
                "Stack Allocation" => "Direct stack memory allocation which could lead to stack overflow",
                "P/Invoke Usage" => "Native code invocation which could introduce security vulnerabilities",
                _ => "Potentially unsafe code pattern detected"
            };
        }

        private string GetUnsafeCodeRecommendation(string issueType)
        {
            return issueType switch
            {
                "Unsafe Code Block" => "Consider using safe alternatives or encapsulate unsafe code in thoroughly tested helper methods",
                "Unsafe Memory Operations" => "Use managed alternatives or implement proper bounds checking and memory management",
                "Fixed Memory Location" => "Consider using Memory<T> or Span<T> for high-performance memory operations",
                "Stack Allocation" => "Use managed arrays or implement size checks before allocation",
                "P/Invoke Usage" => "Ensure proper error handling and input validation around P/Invoke calls",
                _ => "Review and validate the safety of this code pattern"
            };
        }

        private string GetFileOperationDescription(string issueType)
        {
            return issueType switch
            {
                "Unsafe File Operation" => "File operation without proper security checks or error handling",
                "Unsafe Directory Operation" => "Directory operation that could be exploited for unauthorized access",
                "Path Traversal Risk" => "Potential path traversal vulnerability in file system operation",
                "Unchecked FileStream Usage" => "FileStream usage without proper security checks",
                _ => "Potentially unsafe file system operation detected"
            };
        }

        private string GetFileOperationRecommendation(string issueType)
        {
            return issueType switch
            {
                "Unsafe File Operation" => "Implement proper access controls and validate file paths",
                "Unsafe Directory Operation" => "Add proper directory access checks and handle security exceptions",
                "Path Traversal Risk" => "Use Path.GetFullPath() and validate paths against allowed directories",
                "Unchecked FileStream Usage" => "Add proper security checks and use using statements",
                _ => "Implement proper security checks for file system operations"
            };
        }

        private string GetUnityIssueDescription(string issueType)
        {
            return issueType switch
            {
                "Unsafe OnValidate Usage" => "OnValidate contains operations that could be exploited in the editor",
                "Inefficient GameObject.Find" => "Using GameObject.Find which is inefficient and could impact performance",
                "Unsafe SendMessage Usage" => "Using SendMessage which is inefficient and could lead to runtime errors",
                "Unencrypted PlayerPrefs" => "Storing potentially sensitive data in PlayerPrefs without encryption",
                _ => "Potential Unity-specific security or performance issue detected"
            };
        }

        private string GetUnityIssueRecommendation(string issueType)
        {
            return issueType switch
            {
                "Unsafe OnValidate Usage" => "Move heavy operations out of OnValidate and implement proper validation",
                "Inefficient GameObject.Find" => "Cache references using SerializeField or proper dependency injection",
                "Unsafe SendMessage Usage" => "Use direct method calls or proper event systems",
                "Unencrypted PlayerPrefs" => "Implement proper encryption for sensitive data storage",
                _ => "Review Unity-specific best practices for this pattern"
            };
        }

        private bool HasInputValidation(string context)
        {
            var validationPatterns = new[]
            {
        @"try\s*{.*?}\s*catch",
        @"if\s*\([^)]*(?:TryParse|Validate|Check)[^)]*\)",
        @"^\s*if\s*\([^)]+[<>=!]+[^)]+\)",
        @"Regex\s*\.",
        @"\.ToString\([^)]*\)"
    };

            return validationPatterns.Any(pattern =>
                Regex.IsMatch(context, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline));
        }

        private string GetRandomizationRecommendation(string issueType)
        {
            return issueType switch
            {
                "Weak Random Number Generator" => "Use RNGCryptoServiceProvider for secure random numbers",
                "Predictable Game Random" => "Consider if the randomization needs to be cryptographically secure",
                "Unseeded Random" => "Properly seed the random number generator",
                _ => "Review randomization requirements and implement appropriate solution"
            };
        }

        private string GetSerializationRecommendation(string issueType)
        {
            return issueType switch
            {
                "Insecure BinaryFormatter Usage" => "Replace BinaryFormatter with a secure serialization method like JSON.NET or Protocol Buffers",
                "Legacy JavaScript Serializer" => "Use modern serialization libraries with security features",
                "Unconfigured XML Serializer" => "Configure XML serialization with proper security settings",
                "Unsafe JSON Deserialization" => "Disable type handling or implement a custom SerializationBinder",
                _ => "Review and implement secure serialization practices"
            };
        }

        private double CalculateCvssScore(string cvssVector)
        {
            if (string.IsNullOrEmpty(cvssVector))
                return 0.0;

            // Parse CVSS vector and calculate base score
            var parts = cvssVector.Split('/');
            double score = 0.0;

            foreach (var part in parts)
            {
                var metric = part.Split(':');
                if (metric.Length != 2) continue;

                score += metric[1] switch
                {
                    "N" => 0.0,  // None
                    "L" => 0.3,  // Low
                    "H" => 0.6,  // High
                    "C" => 0.9,  // Critical
                    _ => 0.0
                };
            }

            return Math.Min(10.0, score * 1.5);  
        }

        private double CalculateCvssScore(SecurityIssue issue)
        {
            return CalculateCvssScore(issue.CvssVector);
        }



        private void ScanTypes(IEnumerable<ITypeDefinition> types, List<SecurityIssue> issues)
        {
            foreach (var type in types)
            {
                try
                {
                    // Scan the current type
                    string decompiledCode = _decompiler.DecompileType(new ICSharpCode.Decompiler.TypeSystem.FullTypeName(type.FullName)).ToString();
                    string fullTypePath = GetFullTypePath(type);

                    // Scan even if not MonoBehaviour as it might contain sensitive data
                    ScanForApiKeys(decompiledCode, fullTypePath, issues);
                    ScanForHardcodedCredentials(decompiledCode, fullTypePath, issues);
                    ScanForInsecureNetworkCalls(decompiledCode, fullTypePath, issues);

                    // Recursively scan nested types
                    if (type.NestedTypes.Any())
                    {
                        ScanTypes(type.NestedTypes, issues);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error scanning type {type.FullName}: {ex.Message}");
                }
            }
        }

        private string GetFullTypePath(ITypeDefinition type)
        {
            var path = new List<string>();
            var current = type;

            // Add the type name
            path.Add(current.Name);

            // Add containing types (if nested)
            while (current.DeclaringTypeDefinition != null)
            {
                current = current.DeclaringTypeDefinition;
                path.Add(current.Name);
            }

            // Add namespace components
            if (!string.IsNullOrEmpty(current.Namespace))
            {
                // Split namespace by dots and add each component
                var namespaceComponents = current.Namespace.Split('.');
                path.AddRange(namespaceComponents);
            }

            // Reverse and join with dots
            path.Reverse();
            return string.Join(".", path);
        }

        private void ScanForApiKeys(string code, string typePath, List<SecurityIssue> issues)
        {
            var apiKeyPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        // API Keys and Secrets with equals pattern
        { @"(?:api[_-]?key|secret[_-]?key)\s*=\s*[""']([^""'\s\{]+)[""'](?!\s*\+)",
            ("API Key", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
        
        // Access Keys
        { @"access[_-]?key\s*=\s*[""']([^""'\s\{]+)[""'](?!\s*\+)",
            ("Access Key", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
            
        // Service-specific Keys
        { @"(?:publishKey|subscribeKey)\s*=\s*[""']([^""'\s\{]+)[""'](?!\s*\+)",
            ("Service Key", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
            
        // Generic secret/encryption key declarations
        { @"(?:const|private|public|protected).*(?:string|var)\s+.*(?:secret|encryption|private|secure).*key\s*=\s*[""']([^""'\s\{]+)[""']",
            ("Secret Key", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
            
        // Catch potential secrets in variable names
        { @"(?:const|private|public|protected).*(?:string|var)\s+\w*(?:secret|key|token|password|credential)\w*\s*=\s*[""']([^""'\s\{]+)[""']",
            ("Potential Secret", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") },
            
        // Look for long string literals that might be encoded secrets
        { @"(?:const|private|public|protected).*(?:string|var)\s+\w+\s*=\s*[""']([A-Za-z0-9+/=]{32,})[""']",
            ("Potential Encoded Secret", "Medium", "AV:N/AC:L/PR:N/UI:N/S:U/C:M/I:M/A:M") }
    };

            var foundLocations = new HashSet<(int position, string value)>();

            foreach (var pattern in apiKeyPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase | RegexOptions.Singleline);
                foreach (Match match in matches)
                {
                    var foundValue = match.Groups[1].Value;
                    var location = (match.Index, foundValue);

                    // Skip if we've already found this exact value at this position
                    if (foundLocations.Contains(location))
                        continue;

                    // Skip if it's just a variable declaration or URL parameter
                    if (ShouldSkipApiKeyMatch(match.Value, code, match.Index))
                        continue;

                    if (!IsLikelyFalsePositive(foundValue))
                    {
                        foundLocations.Add(location);
                        var score = CalculateCvssScore(pattern.Value.cvss);
                        issues.Add(new SecurityIssue
                        {
                            IssueType = $"Hardcoded {pattern.Value.type}",
                            Location = typePath,
                            Description = $"Found hardcoded {pattern.Value.type.ToLower()} that requires immediate attention.",
                            Severity = pattern.Value.severity,
                            Recommendation = GetEnhancedKeyRecommendation(pattern.Value.type),
                            FoundValue = foundValue,
                            Context = GetExtendedContext(code, match.Index, 200),
                            LineNumber = GetLineNumber(code, match.Index),
                            CvssScore = score,
                            CvssVector = pattern.Value.cvss,
                            AdditionalInfo = new Dictionary<string, string>
                    {
                        { "Category", "Sensitive Data Exposure" },
                        { "Impact", "Potential unauthorized access and data breach" },
                        { "Risk Level", "Immediate attention required" }
                    }
                        });
                    }
                }
            }
        }

        private bool ShouldSkipApiKeyMatch(string matchValue, string code, int matchIndex)
        {
            // Get more context around the match
            var context = GetExtendedContext(code, matchIndex, 200);

            // Skip public key related matches
            if (Regex.IsMatch(context, @"public[-_\s]?key", RegexOptions.IgnoreCase))
                return true;

            // Skip certificates and public key infrastructure
            if (Regex.IsMatch(context, @"(?:certificate|cert|X509|RSA|DSA|ECDSA|Ed25519)\s+.*(?:public|key)",
                RegexOptions.IgnoreCase))
                return true;

            // Skip public key method names and parameters
            if (Regex.IsMatch(context, @"(?:get|set|verify|validate).*public[-_\s]?key", RegexOptions.IgnoreCase))
                return true;

            // Skip if it's a URL parameter name
            if (Regex.IsMatch(context, @"[?&]api[-_]?key=[\w\d]+"))
                return true;

            // Skip if it's part of string concatenation
            if (Regex.IsMatch(context, @"""api[-_]?key""?\s*\+"))
                return true;

            // Skip if it's a variable declaration without value
            if (Regex.IsMatch(context, @"(?:string|var)\s+api[-_]?key\s*;"))
                return true;

            // Skip if it's a parameter name
            if (Regex.IsMatch(context, @"(?:param|parameter|arg|argument|input)\s+api[-_]?key\b"))
                return true;

            // Skip if it's in a URL template
            if (Regex.IsMatch(matchValue, @"\{.*api[-_]?key.*\}"))
                return true;

            // Skip if it's a constant declaration without value
            if (Regex.IsMatch(context, @"(?:const|readonly)\s+\w+\s+api[-_]?key\s*;"))
                return true;

            // Skip if it's part of an API endpoint or URL path
            if (Regex.IsMatch(context, @"(?:endpoint|url|uri|path).*api[-_]?key"))
                return true;

            // Skip cryptographic key generation and key pairs
            if (Regex.IsMatch(context, @"(?:generateKey|createKey|keyPair|KeyPair).*public", RegexOptions.IgnoreCase))
                return true;

            return false;
        }

        private bool IsVariableDeclaration(string context)
        {
            // Check for common variable declaration patterns
            var declarationPatterns = new[]
            {
        @"^\s*(?:private|public|protected)?\s*(?:readonly)?\s*(?:string|var)\s+\w+\s*;",
        @"^\s*(?:private|public|protected)?\s*(?:readonly)?\s*(?:string|var)\s+\w+\s*=\s*null\s*;",
        @"^\s*(?:private|public|protected)?\s*(?:readonly)?\s*(?:string|var)\s+\w+\s*=\s*string\.Empty\s*;"
    };

            return declarationPatterns.Any(pattern =>
                Regex.IsMatch(context.Trim(), pattern, RegexOptions.IgnoreCase));
        }

        private string GetEnhancedKeyRecommendation(string keyType)
        {
            var recommendations = keyType.ToLower() switch
            {
                var s when s.Contains("api key") => new[]
                {
            "Immediate Actions:",
            "• Revoke and rotate the exposed API key immediately",
            "• Remove the hardcoded key from the codebase",
            "",
            "Security Measures:",
            "• Move the API key to a secure secret management system",
            "• Use environment variables or encrypted configuration files",
            "• Implement API key rotation policies",
            "",
            "Best Practices:",
            "• Add runtime checks to prevent key logging",
            "• Implement access logging for API key usage",
            "• Consider using temporary/session-based keys where possible"
        },

                var s when s.Contains("secret") || s.Contains("access key") => new[]
                {
            "Critical Actions:",
            "• Rotate all exposed secrets/access keys immediately",
            "• Review access logs for unauthorized usage",
            "",
            "Implementation:",
            "• Use a secure secret management service (e.g., Azure Key Vault, AWS Secrets Manager)",
            "• Implement proper access controls and audit logging",
            "• Set up automated key rotation",
            "",
            "Additional Steps:",
            "• Review systems that may have logged this key",
            "• Implement secret scanning in CI/CD pipeline"
        },

                _ => new[]
                {
            "Required Actions:",
            "• Remove the hardcoded sensitive value",
            "• Implement proper secret management",
            "",
            "Security Steps:",
            "• Review security logs for unauthorized access",
            "• Implement automated secret detection",
            "• Set up proper access controls"
        }
            };

            return string.Join("\n", recommendations);
        }

        private string GetCryptoRecommendation(string issueType) => issueType switch
        {
            "Weak Hashing (MD5)" =>
                "• Replace MD5 with SHA256 or better\n" +
                "• For password hashing, use specialized algorithms like Argon2, BCrypt, or PBKDF2\n" +
                "• Implement salting for password hashes\n" +
                "• Consider using a dedicated password hashing library",

            "Weak Hashing (SHA1)" =>
                "• Replace SHA1 with SHA256 or better\n" +
                "• Use SHA512 for more security-critical applications\n" +
                "• Consider using HMAC for message authentication",

            "Insecure Random Generation" =>
                "• Replace Random with RNGCryptoServiceProvider or RandomNumberGenerator\n" +
                "• Use GetBytes() method for generating random values\n" +
                "• Ensure proper seeding of cryptographic random numbers",

            "Hardcoded Cryptographic Material" =>
                "• Remove hardcoded cryptographic material\n" +
                "• Use secure key management solutions\n" +
                "• Implement proper key rotation\n" +
                "• Store keys in secure configuration or key vault",

            "Obsolete Encryption Algorithm" =>
                "• Replace with AES (AES-256-GCM preferred)\n" +
                "• Use proper key sizes (256 bits recommended)\n" +
                "• Implement proper IV handling\n" +
                "• Use authenticated encryption modes",

            "Insecure Cipher Mode (ECB)" =>
                "• Replace ECB with GCM or CBC mode\n" +
                "• Implement proper IV handling\n" +
                "• Use authenticated encryption\n" +
                "• Consider using higher-level encryption libraries",

            _ => "Review and update cryptographic implementations according to current best practices"
        };

        private string GetInputValidationRecommendation(string issueType) => issueType switch
        {
            "Path Traversal Risk" =>
                "• Use Path.GetFullPath() to canonicalize paths\n" +
                "• Implement whitelist of allowed paths\n" +
                "• Validate against directory traversal sequences\n" +
                "• Use Path.Combine() safely",

            "SQL Injection Risk" =>
                "• Use parameterized queries\n" +
                "• Implement prepared statements\n" +
                "• Avoid string concatenation in queries\n" +
                "• Use an ORM when possible",

            "Command Injection Risk" =>
                "• Validate and sanitize all command inputs\n" +
                "• Use allowlist for permitted commands\n" +
                "• Avoid command injection entirely if possible\n" +
                "• Consider using API alternatives",

            "Unvalidated Redirect" =>
                "• Implement URL whitelist\n" +
                "• Validate all redirect URLs\n" +
                "• Use relative paths when possible\n" +
                "• Add redirect warnings for external URLs",

            "XML External Entity Risk" =>
                "• Disable DTD processing\n" +
                "• Use safe XML reader settings\n" +
                "• Implement XXE prevention\n" +
                "• Consider using JSON instead",

            _ => "Implement proper input validation and sanitization"
        };

        private string GetCryptoImpact(string issueType) => issueType switch
        {
            "Weak Hashing (MD5)" => "Hash collisions possible, leading to potential integrity compromises",
            "Weak Hashing (SHA1)" => "Known vulnerabilities could lead to hash collisions",
            "Insecure Random Generation" => "Predictable values could lead to security bypasses",
            "Hardcoded Cryptographic Material" => "Keys could be extracted from compiled code",
            "Obsolete Encryption Algorithm" => "Known vulnerabilities could lead to data exposure",
            "Insecure Cipher Mode (ECB)" => "Pattern recognition possible in encrypted data",
            _ => "Potential cryptographic weakness"
        };

        private string GetInputValidationImpact(string issueType) => issueType switch
        {
            "Path Traversal Risk" => "Unauthorized file system access possible",
            "SQL Injection Risk" => "Database compromise and data breach possible",
            "Command Injection Risk" => "Arbitrary command execution on host system",
            "Unvalidated Redirect" => "Phishing and redirect attacks possible",
            "XML External Entity Risk" => "File disclosure and server-side request forgery risks",
            _ => "Security bypass through invalid input"
        };

        private string GetInputValidationDescription(string issueType) => issueType switch
        {
            "Path Traversal Risk" => "Potential directory traversal vulnerability through unvalidated file paths",
            "SQL Injection Risk" => "Possible SQL injection through unparameterized queries",
            "Command Injection Risk" => "Potential command injection through unvalidated input",
            "Unvalidated Redirect" => "Open redirect vulnerability through unvalidated URL",
            "XML External Entity Risk" => "Potential XXE vulnerability through unsafe XML parsing",
            _ => "Input validation vulnerability detected"
        };



        private void ScanForHardcodedCredentials(string code, string typePath, List<SecurityIssue> issues)
        {
            var credentialPatterns = new Dictionary<string, (string type, string severity, string cvss)>
    {
        // Password patterns (excluding API keys)
        { @"(?<!api[_-]?|secret[_-]?|access[_-]?)(?:password|pwd)\s*=\s*[""']([^""']{8,})[""']",
            ("Password", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") },
        
        // Username patterns
        { @"username\s*=\s*[""']([^""']+@[^""']+)[""']",
            ("Email Username", "High", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") },
        
        // Database credentials (excluding API patterns)
        { @"(?<!api[_-]?)connection[_-]?string\s*=\s*[""']([^""']+)[""']",
            ("Connection String", "Critical", "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") }
    };

            var foundLocations = new HashSet<(int position, string value)>();

            foreach (var pattern in credentialPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var foundValue = match.Groups[1].Value;
                    var location = (match.Index, foundValue);

                    // Skip if we've already found this exact value at this position
                    if (foundLocations.Contains(location))
                        continue;

                    if (!IsLikelyFalsePositive(foundValue))
                    {
                        foundLocations.Add(location);
                        issues.Add(new SecurityIssue
                        {
                            IssueType = $"Hardcoded {pattern.Value.type}",
                            Location = typePath,
                            Description = $"Hardcoded {pattern.Value.type.ToLower()} found in code",
                            Severity = pattern.Value.severity,
                            Recommendation = GetRecommendation(pattern.Value.type),
                            FoundValue = foundValue,
                            Context = GetExtendedContext(code, match.Index, 200),
                            LineNumber = GetLineNumber(code, match.Index),
                            CvssScore = CalculateCvssScore(pattern.Value.cvss),
                            CvssVector = pattern.Value.cvss,
                            AdditionalInfo = new Dictionary<string, string>
                    {
                        { "Category", "Credentials" },
                        { "Impact", "Potential credential exposure" }
                    }
                        });
                    }
                }
            }
        }

        private void ScanForInsecureNetworkCalls(string code, string typePath, List<SecurityIssue> issues)
        {
            var networkPatterns = new Dictionary<string, (string type, string severity)>
        {
            { @"(http://[^\s""']+)", ("Insecure HTTP URL", "High") },
            { @"WWW\([""']([^""']+)[""']\)", ("Unity WWW Class Usage", "Medium") },
            { @"UnityWebRequest.*AllowInsecureHTTP\s*=\s*true", ("Insecure HTTP Allowed", "High") },
            { @"WebClient\.DownloadString\([""']http://", ("Insecure WebClient Usage", "High") },
            { @"new\s+Socket\s*\([^)]*\)", ("Raw Socket Usage", "Medium") },
            { @"NetworkCredential\([^)]+\)", ("Hardcoded Network Credentials", "Critical") }
        };

            foreach (var pattern in networkPatterns)
            {
                var matches = Regex.Matches(code, pattern.Key, RegexOptions.IgnoreCase);
                foreach (Match match in matches)
                {
                    var foundValue = match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                    var context = GetExtendedContext(code, match.Index, 100);

                    issues.Add(new SecurityIssue
                    {
                        IssueType = pattern.Value.type,
                        Location = typePath,  // Use the passed-in type path
                        Description = GetNetworkIssueDescription(pattern.Value.type),
                        Severity = pattern.Value.severity,
                        Recommendation = GetNetworkRecommendation(pattern.Value.type),
                        FoundValue = foundValue,
                        Context = context,
                        LineNumber = GetLineNumber(code, match.Index)
                    });
                }
            }
        }

        private bool IsLikelyFalsePositive(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return true;
            if (value.Length < 8) return true;

            // Check for public key indicators
            var publicKeyPatterns = new[]
            {
        @"^ssh-rsa\s+",                    // SSH RSA public key format
        @"^ssh-ed25519\s+",               // SSH Ed25519 public key format
        @"^ecdsa-sha2-\w+\s+",            // SSH ECDSA public key format
        @"^pk_\w+",                       // Common public key prefixes
        @"^MIIBIj\w+",                    // RSA public key (PEM format)
        @"^MIIBCg\w+",                    // RSA public key (DER format)
        @"^publicKey",                    // Public key variable names
        @"^PUBLIC_KEY",
        @"^PUBLIC-KEY",
        @"^public_key",
        @"^public-key"
    };

            // Return true (false positive) if it matches any public key pattern
            if (publicKeyPatterns.Any(pattern => Regex.IsMatch(value, pattern)))
                return true;

            // Check common public key contexts in the value
            var publicKeyContexts = new[]
            {
        "public key",
        "PUBLIC KEY",
        "Public Key",
        "PublicKey",
        "PUBLICKEY",
        "public-key",
        "PUBLIC-KEY",
        "public_key",
        "PUBLIC_KEY"
    };

            if (publicKeyContexts.Any(context => value.Contains(context, StringComparison.OrdinalIgnoreCase)))
                return true;

            // Only check common false positives if the value doesn't look like a real key
            if (!Regex.IsMatch(value, @"^[A-Za-z0-9+/=_\-]{16,}$"))
            {
                var commonFalsePositives = new[]
                {
            "placeholder",
            "example",
            "test",
            "demo",
            "sample",
            "default",
            "yourkey",
            "your-key",
            "your_key",
            "public_key",
            "pk_",
            "PUBLIC_KEY",
            "publickey",
            "public-key",
            "PUBLICKEY"
        };

                if (commonFalsePositives.Any(fp =>
                    value.ToLowerInvariant().Contains(fp.ToLowerInvariant())))
                    return true;
            }

            // Template strings
            if (value.Contains("${")) return true;
            if (value.Contains("{{")) return true;
            if (value.Contains("{id}")) return true;

            return false;
        }

        private string GetExtendedContext(string code, int position, int radius)
        {
            // Find the start of the line
            var lineStart = position;
            while (lineStart > 0 && code[lineStart - 1] != '\n')
                lineStart--;

            // Find the end of the line
            var lineEnd = position;
            while (lineEnd < code.Length && code[lineEnd] != '\n')
                lineEnd++;

            // Get additional lines before and after
            var start = Math.Max(0, lineStart - radius);
            var end = Math.Min(code.Length, lineEnd + radius);

            return code.Substring(start, end - start)
                      .Replace("\r", "")
                      .Trim();
        }

        private int GetLineNumber(string code, int position)
        {
            return code.Substring(0, position).Count(c => c == '\n') + 1;
        }

        private string GetRecommendation(string issueType)
        {
            return issueType.ToLower() switch
            {
                var s when s.Contains("secret") || s.Contains("access key") =>
                    "Store secret keys and access keys in a secure configuration system or key vault. Never include these in source code.",

                var s when s.Contains("api key") =>
                    "Store API keys in a secure configuration system. Consider using Unity's Scriptable Objects or encrypted PlayerPrefs for development, and a proper secret management solution for production.",

                var s when s.Contains("endpoint") =>
                    "Consider moving API endpoints to configuration files. Ensure proper HTTPS usage and certificate validation.",

                var s when s.Contains("environment") =>
                    "Move environment configuration to secure configuration files or environment variables. Consider using Unity's Scriptable Objects for development.",

                _ => "Review this potential sensitive data and ensure it's properly secured if needed."
            };
        }

        private string GetNetworkIssueDescription(string issueType)
        {
            return issueType switch
            {
                "Insecure HTTP URL" =>
                    "Using unencrypted HTTP protocol which can expose data to interception",

                "Unity WWW Class Usage" =>
                    "The WWW class is deprecated and may have security vulnerabilities",

                "Insecure HTTP Allowed" =>
                    "HTTPS certificate validation is disabled, making the connection vulnerable to man-in-the-middle attacks",

                "Raw Socket Usage" =>
                    "Direct socket usage should be carefully reviewed for security implications",

                _ => "Potentially insecure network communication detected"
            };
        }

        private double CalculateFalsePositiveConfidence(SecurityIssue issue)
        {
            double confidence = 1.0;

            // Check the context for test/mock indicators
            if (issue.Context != null)
            {
                if (issue.Context.Contains("test", StringComparison.OrdinalIgnoreCase) ||
                    issue.Context.Contains("mock", StringComparison.OrdinalIgnoreCase) ||
                    issue.Context.Contains("example", StringComparison.OrdinalIgnoreCase) ||
                    issue.Context.Contains("sample", StringComparison.OrdinalIgnoreCase))
                {
                    confidence -= 0.3;
                }

                // Check for debug/development indicators
                if (issue.Context.Contains("debug", StringComparison.OrdinalIgnoreCase) ||
                    issue.Context.Contains("dev", StringComparison.OrdinalIgnoreCase))
                {
                    confidence -= 0.2;
                }

                // Check for comments indicating test/temporary code
                if (issue.Context.Contains("//") && (
                    issue.Context.Contains("TODO", StringComparison.OrdinalIgnoreCase) ||
                    issue.Context.Contains("TEMP", StringComparison.OrdinalIgnoreCase) ||
                    issue.Context.Contains("FIXME", StringComparison.OrdinalIgnoreCase)))
                {
                    confidence -= 0.2;
                }
            }

            // Consider the issue type
            if (issue.IssueType != null)
            {
                // Higher confidence for critical security issues
                if (issue.IssueType.Contains("Critical", StringComparison.OrdinalIgnoreCase) ||
                    issue.IssueType.Contains("Insecure", StringComparison.OrdinalIgnoreCase) ||
                    issue.IssueType.Contains("Unsafe", StringComparison.OrdinalIgnoreCase))
                {
                    confidence += 0.2;
                }
            }

            // Consider the location
            if (issue.Location != null)
            {
                // Lower confidence for test classes/namespaces
                if (issue.Location.Contains("Test", StringComparison.OrdinalIgnoreCase) ||
                    issue.Location.Contains("Mock", StringComparison.OrdinalIgnoreCase) ||
                    issue.Location.Contains("Example", StringComparison.OrdinalIgnoreCase))
                {
                    confidence -= 0.3;
                }

                // Higher confidence for security-related classes
                if (issue.Location.Contains("Security", StringComparison.OrdinalIgnoreCase) ||
                    issue.Location.Contains("Auth", StringComparison.OrdinalIgnoreCase) ||
                    issue.Location.Contains("Crypt", StringComparison.OrdinalIgnoreCase))
                {
                    confidence += 0.1;
                }
            }

            // Consider the severity
            confidence += issue.Severity switch
            {
                "Critical" => 0.2,
                "High" => 0.1,
                "Medium" => 0.0,
                "Low" => -0.1,
                _ => 0.0
            };

            // Ensure confidence stays within 0.0 to 1.0 range
            return Math.Max(0.0, Math.Min(1.0, confidence));
        }

        private string GetNetworkRecommendation(string issueType)
        {
            return issueType switch
            {
                "Insecure HTTP URL" =>
                    "Use HTTPS instead of HTTP. Ensure all network communications are encrypted.",

                "Unity WWW Class Usage" =>
                    "Replace WWW with UnityWebRequest and ensure HTTPS is used.",

                "Insecure HTTP Allowed" =>
                    "Remove AllowInsecureHTTP setting and properly handle certificates.",

                "Raw Socket Usage" =>
                    "Consider using higher-level networking APIs with built-in security features.",

                _ => "Implement proper security measures for all network communications."
            };
        }
    }
}