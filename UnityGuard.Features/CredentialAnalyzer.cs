using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.TypeSystem;

namespace RetroDev.UnityGuard.UnityGuard.Features
{
    public class CredentialAnalyzer
    {
        private readonly SyntaxTree _syntaxTree;
        private readonly string _code;
        private readonly Dictionary<string, CredentialInfo> _credentials;

        public CredentialAnalyzer(SyntaxTree syntaxTree, string code)
        {
            _syntaxTree = syntaxTree;
            _code = code;
            _credentials = new Dictionary<string, CredentialInfo>();
        }

        public class CredentialInfo
        {
            public string Name { get; set; }
            public string Type { get; set; }
            public string Value { get; set; }
            public bool IsHardcoded { get; set; }
            public bool IsEncrypted { get; set; }
            public string StorageMethod { get; set; }
            public int LineNumber { get; set; }
            public string Context { get; set; }
            public float RiskScore { get; set; }
        }

        public float[] AnalyzeCredentialMetrics()
        {
            var visitor = new CredentialVisitor(this);
            _syntaxTree.AcceptVisitor(visitor);

            var metrics = new float[20];

            // 1. Hardcoded Credential Rate
            metrics[0] = AnalyzeHardcodedRate();

            // 2. Encryption Coverage
            metrics[1] = AnalyzeEncryptionCoverage();

            // 3. Secure Storage Usage
            metrics[2] = AnalyzeSecureStorageRate();

            // 4. Password Handling Score
            metrics[3] = AnalyzePasswordHandling();

            // 5. API Key Security
            metrics[4] = AnalyzeApiKeySecurity();

            // 6. Token Management
            metrics[5] = AnalyzeTokenManagement();

            // 7. Configuration Security
            metrics[6] = AnalyzeConfigSecurity();

            // 8. Secret Dispersal Rate
            metrics[7] = AnalyzeSecretDispersal();

            // 9. Credential Rotation Support
            metrics[8] = AnalyzeRotationSupport();

            // 10. Access Control Coverage
            metrics[9] = AnalyzeAccessControl();

            // 11. Credential Transmission Security
            metrics[10] = AnalyzeTransmissionSecurity();

            // 12. Storage Encryption Rate
            metrics[11] = AnalyzeStorageEncryption();

            // 13. Key Derivation Usage
            metrics[12] = AnalyzeKeyDerivation();

            // 14. Secure Random Usage
            metrics[13] = AnalyzeSecureRandom();

            // 15. Credential Validation
            metrics[14] = AnalyzeCredentialValidation();

            // 16. Error Handling Security
            metrics[15] = AnalyzeErrorHandling();

            // 17. Logging Security
            metrics[16] = AnalyzeLoggingSecurity();

            // 18. Memory Protection
            metrics[17] = AnalyzeMemoryProtection();

            // 19. Cleanup Practices
            metrics[18] = AnalyzeCleanupPractices();

            // 20. Overall Security Score
            metrics[19] = CalculateOverallScore();

            return metrics;
        }

        private class CredentialVisitor : DepthFirstAstVisitor
        {
            private readonly CredentialAnalyzer _analyzer;
            private readonly HashSet<string> _credentialPatterns = new HashSet<string>
            {
                "password", "secret", "key", "token", "api", "credential", "auth",
                "certificate", "private", "pwd", "passwd"
            };

            public CredentialVisitor(CredentialAnalyzer analyzer)
            {
                _analyzer = analyzer;
            }

            public override void VisitFieldDeclaration(FieldDeclaration fieldDecl)
            {
                foreach (var variable in fieldDecl.Variables)
                {
                    if (IsCredentialVariable(variable))
                    {
                        var info = new CredentialInfo
                        {
                            Name = variable.Name,
                            Type = fieldDecl.ReturnType.ToString(),
                            Value = variable.Initializer?.ToString(),
                            LineNumber = fieldDecl.StartLocation.Line,
                            Context = GetContext(fieldDecl),
                            IsHardcoded = IsHardcodedValue(variable),
                            IsEncrypted = IsEncryptedValue(variable),
                            StorageMethod = DetermineStorageMethod(fieldDecl)
                        };

                        info.RiskScore = CalculateCredentialRisk(info);
                        _analyzer._credentials[variable.Name] = info;
                    }
                }
                base.VisitFieldDeclaration(fieldDecl);
            }

            private bool IsCredentialVariable(VariableInitializer variable)
            {
                var name = variable.Name.ToLower();
                return _credentialPatterns.Any(pattern => name.Contains(pattern));
            }

            private bool IsHardcodedValue(VariableInitializer variable)
            {
                if (variable.Initializer == null) return false;

                var value = variable.Initializer.ToString();
                return !value.Contains("Environment") &&
                       !value.Contains("Configuration") &&
                       !value.Contains("GetValue") &&
                       !value.Contains("Load");
            }

            private bool IsEncryptedValue(VariableInitializer variable)
            {
                if (variable.Initializer == null) return false;

                var context = GetContext(variable.Parent);
                return context.Contains("Encrypt") ||
                       context.Contains("Hash") ||
                       context.Contains("Protect") ||
                       context.Contains("Secure");
            }

            private string DetermineStorageMethod(AstNode node)
            {
                var context = GetContext(node);
                if (context.Contains("PlayerPrefs")) return "PlayerPrefs";
                if (context.Contains("SecureStorage")) return "SecureStorage";
                if (context.Contains("KeyChain")) return "KeyChain";
                if (context.Contains("Registry")) return "Registry";
                if (context.Contains("File")) return "File";
                return "Memory";
            }

            private string GetContext(AstNode node)
            {
                var startLine = Math.Max(0, node.StartLocation.Line - 2);
                var endLine = Math.Min(_analyzer._code.Split('\n').Length, node.EndLocation.Line + 2);
                var lines = _analyzer._code.Split('\n');
                return string.Join("\n", lines.Skip(startLine).Take(endLine - startLine));
            }
        }

        private float AnalyzeHardcodedRate()
        {
            if (!_credentials.Any()) return 0;
            return _credentials.Count(c => c.Value.IsHardcoded) / (float)_credentials.Count;
        }

        private float AnalyzeEncryptionCoverage()
        {
            if (!_credentials.Any()) return 0;
            return _credentials.Count(c => c.Value.IsEncrypted) / (float)_credentials.Count;
        }

        private float AnalyzeSecureStorageRate()
        {
            if (!_credentials.Any()) return 0;
            var secureStorageMethods = new[] { "SecureStorage", "KeyChain" };
            return _credentials.Count(c => secureStorageMethods.Contains(c.Value.StorageMethod)) / (float)_credentials.Count;
        }

        private float AnalyzePasswordHandling()
        {
            var passwordVars = _credentials.Values.Where(c =>
                c.Name.ToLower().Contains("password") ||
                c.Name.ToLower().Contains("pwd"));

            if (!passwordVars.Any()) return 1; // No passwords to analyze

            float score = 1;
            foreach (var pwd in passwordVars)
            {
                if (!pwd.IsEncrypted) score -= 0.3f;
                if (pwd.IsHardcoded) score -= 0.3f;
                if (pwd.StorageMethod == "Memory") score -= 0.2f;
            }

            return Math.Max(0, score);
        }

        private float AnalyzeApiKeySecurity()
        {
            var apiKeys = _credentials.Values.Where(c =>
                c.Name.ToLower().Contains("api") &&
                c.Name.ToLower().Contains("key"));

            if (!apiKeys.Any()) return 1;

            float score = 1;
            foreach (var key in apiKeys)
            {
                if (key.IsHardcoded) score -= 0.4f;
                if (!key.IsEncrypted) score -= 0.3f;
                if (key.StorageMethod == "Memory" || key.StorageMethod == "File") score -= 0.2f;
            }

            return Math.Max(0, score);
        }

        private float AnalyzeTokenManagement()
        {
            var tokens = _credentials.Values.Where(c => c.Name.ToLower().Contains("token"));

            if (!tokens.Any()) return 1;

            float score = 1;
            foreach (var token in tokens)
            {
                if (token.IsHardcoded) score -= 0.4f;
                if (!token.IsEncrypted) score -= 0.3f;
                if (token.StorageMethod == "Memory") score -= 0.2f;
            }

            return Math.Max(0, score);
        }

        private float AnalyzeConfigSecurity()
        {
            var configCreds = _credentials.Values.Where(c =>
                c.Context.Contains("config") ||
                c.Context.Contains("settings"));

            if (!configCreds.Any()) return 1;

            float score = 1;
            foreach (var cred in configCreds)
            {
                if (cred.IsHardcoded) score -= 0.3f;
                if (!cred.IsEncrypted) score -= 0.3f;
                if (cred.StorageMethod == "File") score -= 0.2f;
            }

            return Math.Max(0, score);
        }

        private float AnalyzeSecretDispersal()
        {
            // Check how many different storage locations are used
            var uniqueStorageLocations = _credentials.Values
                .Select(c => c.StorageMethod)
                .Distinct()
                .Count();

            // More dispersal = higher risk
            return 1 - (Math.Min(uniqueStorageLocations, 5) / 5.0f);
        }

        private float AnalyzeRotationSupport()
        {
            var rotationPatterns = new[] {
                "rotate", "refresh", "renew", "update", "generate"
            };

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (rotationPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeAccessControl()
        {
            var accessControlPatterns = new[] {
                "private", "protected", "internal", "readonly", "const"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (accessControlPatterns.Any(p => cred.Context.Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeTransmissionSecurity()
        {
            var transmissionPatterns = new[] {
                "http://", "ftp://", "net.socket", "send", "transfer"
            };

            if (!_credentials.Any()) return 1;

            float riskScore = 0;
            foreach (var cred in _credentials.Values)
            {
                if (transmissionPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    riskScore += 1.0f / _credentials.Count;
                }
            }

            return 1 - riskScore;
        }

        private float AnalyzeStorageEncryption()
        {
            var secureStoragePatterns = new[] {
                "encrypt", "protect", "secure", "hash"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (secureStoragePatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeKeyDerivation()
        {
            var keyDerivationPatterns = new[] {
                "pbkdf2", "bcrypt", "scrypt", "argon2", "derivekey"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (keyDerivationPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeSecureRandom()
        {
            var secureRandomPatterns = new[] {
                "rngcrytoserviceprovider", "randomnumbergenerator", "securerandom"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (secureRandomPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeCredentialValidation()
        {
            var validationPatterns = new[] {
                "validate", "verify", "check", "assert"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (validationPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeErrorHandling()
        {
            var errorHandlingPatterns = new[] {
                "try", "catch", "finally", "throw"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (errorHandlingPatterns.Any(p => cred.Context.Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeLoggingSecurity()
        {
            var loggingPatterns = new[] {
                "debug.log", "console.write", "log.", "trace."
            };

            if (!_credentials.Any()) return 1;

            float riskScore = 0;
            foreach (var cred in _credentials.Values)
            {
                if (loggingPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    riskScore += 1.0f / _credentials.Count;
                }
            }

            // Inverse the score as logging credentials is a risk
            return 1 - riskScore;
        }

        private float AnalyzeMemoryProtection()
        {
            var protectionPatterns = new[] {
                "securestring", "marshal", "zeromemory", "protect"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (protectionPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float AnalyzeCleanupPractices()
        {
            var cleanupPatterns = new[] {
                "dispose", "clear", "cleanup", "reset"
            };

            if (!_credentials.Any()) return 1;

            float score = 0;
            foreach (var cred in _credentials.Values)
            {
                if (cleanupPatterns.Any(p => cred.Context.ToLower().Contains(p)))
                {
                    score += 1.0f / _credentials.Count;
                }
            }

            return score;
        }

        private float CalculateOverallScore()
        {
            if (!_credentials.Any()) return 1;

            float totalRisk = 0;
            foreach (var cred in _credentials.Values)
            {
                float riskScore = 0;

                // Accumulate risk factors
                if (cred.IsHardcoded) riskScore += 0.3f;
                if (!cred.IsEncrypted) riskScore += 0.3f;
                if (cred.StorageMethod == "Memory") riskScore += 0.2f;
                if (cred.StorageMethod == "File") riskScore += 0.2f;

                // Adjust for credential type
                if (cred.Name.ToLower().Contains("password")) riskScore *= 1.2f;
                if (cred.Name.ToLower().Contains("token")) riskScore *= 1.1f;
                if (cred.Name.ToLower().Contains("api")) riskScore *= 1.1f;

                totalRisk += riskScore;
            }

            // Normalize to 0-1 range
            return Math.Max(0, 1 - (totalRisk / _credentials.Count));
        }

        public static float CalculateCredentialRisk(CredentialInfo info)
        {
            float risk = 0.0f;

            // Base risk for credential type
            if (info.Name.ToLower().Contains("password")) risk += 0.3f;
            if (info.Name.ToLower().Contains("apikey")) risk += 0.25f;
            if (info.Name.ToLower().Contains("token")) risk += 0.2f;
            if (info.Name.ToLower().Contains("secret")) risk += 0.25f;

            // Risk factors
            if (info.IsHardcoded) risk += 0.3f;
            if (!info.IsEncrypted) risk += 0.2f;

            // Storage method risks
            switch (info.StorageMethod.ToLower())
            {
                case "memory":
                    risk += 0.15f;
                    break;
                case "file":
                    risk += 0.25f;
                    break;
                case "playerprefs":
                    risk += 0.2f;
                    break;
                case "registry":
                    risk += 0.1f;
                    break;
            }

            // Context-based risks
            if (info.Context.ToLower().Contains("debug.log")) risk += 0.2f;
            if (info.Context.ToLower().Contains("print")) risk += 0.15f;
            if (!info.Context.ToLower().Contains("try") &&
                !info.Context.ToLower().Contains("catch")) risk += 0.1f;

            // Normalize to 0-1 range
            return Math.Min(1.0f, risk);
        }
    }
}
