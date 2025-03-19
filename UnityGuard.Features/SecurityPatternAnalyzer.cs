using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.TypeSystem;

namespace RetroDev.UnityGuard.UnityGuard.Features
{
    public class SecurityPatternAnalyzer
    {
        private readonly SyntaxTree _syntaxTree;
        private readonly string _code;
        private readonly Dictionary<string, List<SecurityPattern>> _detectedPatterns;

        public SecurityPatternAnalyzer(SyntaxTree syntaxTree, string code)
        {
            _syntaxTree = syntaxTree;
            _code = code;
            _detectedPatterns = new Dictionary<string, List<SecurityPattern>>();
        }

        /// <summary>
        /// Calculates security pattern metrics for use in analysis
        /// </summary>
        public float[] CalculateSecurityMetrics()
        {
            var metrics = new float[10];

            // 1. Authentication Pattern Complexity
            metrics[0] = CalculateAuthenticationComplexity();

            // 2. Validation Coverage
            metrics[1] = CalculateValidationCoverage();

            // 3. Cryptographic Implementation Score
            metrics[2] = AnalyzeCryptographicImplementation();

            // 4. Error Handling Robustness
            metrics[3] = CalculateErrorHandlingRobustness();

            // 5. Security Control Distribution
            metrics[4] = AnalyzeSecurityControlDistribution();

            // 6. Pattern Implementation Safety
            metrics[5] = CalculatePatternSafetyScore();

            // 7. Security Pattern Diversity
            metrics[6] = AnalyzePatternDiversity();

            // 8. Configuration Security Score
            metrics[7] = CalculateConfigurationSecurity();

            // 9. Cross-Pattern Integration
            metrics[8] = AnalyzeCrossPatternIntegration();

            // 10. Security Pattern Maintenance
            metrics[9] = AnalyzePatternMaintenance();

            return metrics;
        }

        private float CalculateAuthenticationComplexity()
        {
            var visitor = new AuthenticationComplexityVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.Complexity);
        }

        private float CalculateValidationCoverage()
        {
            var visitor = new ValidationCoverageVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            float coverage = visitor.ValidatedInputs / (float)Math.Max(1, visitor.TotalInputs);
            return NormalizeMetric(coverage);
        }

        private float AnalyzeCryptographicImplementation()
        {
            var visitor = new CryptoImplementationVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateSecurityScore();
        }

        private float CalculateErrorHandlingRobustness()
        {
            var visitor = new ErrorHandlingVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateRobustnessScore();
        }

        private float AnalyzeSecurityControlDistribution()
        {
            var visitor = new SecurityControlVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateDistributionScore();
        }

        private float CalculatePatternSafetyScore()
        {
            var result = AnalyzePatterns();
            if (!result.RiskScores.Any()) return 0;
            return 1 - result.RiskScores.Average(x => x.Value);
        }

        private float AnalyzePatternDiversity()
        {
            var result = AnalyzePatterns();
            int uniquePatterns = new HashSet<string>(
                result.AuthenticationPatterns.Concat(
                result.ValidationPatterns).Concat(
                result.CryptographyPatterns).Concat(
                result.ErrorHandlingPatterns).Concat(
                result.ConfigurationPatterns)
                .Select(p => p.PatternType)
            ).Count;

            return NormalizeMetric(uniquePatterns);
        }

        private float CalculateConfigurationSecurity()
        {
            var visitor = new ConfigurationSecurityVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateSecurityScore();
        }

        private float AnalyzeCrossPatternIntegration()
        {
            var visitor = new CrossPatternVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateIntegrationScore();
        }

        private float AnalyzePatternMaintenance()
        {
            var visitor = new PatternMaintenanceVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateMaintenanceScore();
        }

        private float NormalizeMetric(float value)
        {
            const float maxValue = 50.0f;
            return Math.Min(value / maxValue, 1.0f);
        }

        // New visitor classes for metrics calculation
        private class AuthenticationComplexityVisitor : DepthFirstAstVisitor
        {
            public int Complexity { get; private set; } = 0;
            private HashSet<string> _authMethods = new HashSet<string> {
                "authenticate", "authorize", "login", "signin", "verify"
            };

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                string methodName = methodDeclaration.Name.ToLower();
                if (_authMethods.Any(m => methodName.Contains(m)))
                {
                    Complexity += CalculateMethodComplexity(methodDeclaration);
                }
                base.VisitMethodDeclaration(methodDeclaration);
            }

            private int CalculateMethodComplexity(MethodDeclaration method)
            {
                int complexity = 1;
                var body = method.ToString().ToLower();

                if (body.Contains("hash")) complexity++;
                if (body.Contains("salt")) complexity++;
                if (body.Contains("encrypt")) complexity++;
                if (body.Contains("token")) complexity++;
                if (body.Contains("session")) complexity++;

                return complexity;
            }
        }

        private class ValidationCoverageVisitor : DepthFirstAstVisitor
        {
            public int TotalInputs { get; private set; } = 0;
            public int ValidatedInputs { get; private set; } = 0;

            public override void VisitParameterDeclaration(ParameterDeclaration parameterDeclaration)
            {
                TotalInputs++;
                var parentMethod = parameterDeclaration.Parent as MethodDeclaration;
                if (parentMethod != null && HasValidation(parentMethod, parameterDeclaration.Name))
                {
                    ValidatedInputs++;
                }
                base.VisitParameterDeclaration(parameterDeclaration);
            }

            private bool HasValidation(MethodDeclaration method, string paramName)
            {
                var body = method.ToString().ToLower();
                return body.Contains($"validate({paramName}") ||
                       body.Contains($"check({paramName}") ||
                       body.Contains($"if({paramName}");
            }
        }

        private class CryptoImplementationVisitor : DepthFirstAstVisitor
        {
            private int _secureImplementations = 0;
            private int _totalImplementations = 0;
            private HashSet<string> _secureAlgorithms = new HashSet<string> {
                "aes", "sha256", "sha512", "rsa", "ecdsa"
            };
            private HashSet<string> _insecureAlgorithms = new HashSet<string> {
                "md5", "sha1", "des", "rc4"
            };

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                var methodName = invocation.ToString().ToLower();
                if (IsCryptoOperation(methodName))
                {
                    _totalImplementations++;
                    if (IsSecureImplementation(methodName))
                    {
                        _secureImplementations++;
                    }
                }
                base.VisitInvocationExpression(invocation);
            }

            private bool IsCryptoOperation(string method)
            {
                return _secureAlgorithms.Any(a => method.Contains(a)) ||
                       _insecureAlgorithms.Any(a => method.Contains(a));
            }

            private bool IsSecureImplementation(string method)
            {
                return _secureAlgorithms.Any(a => method.Contains(a)) &&
                       !_insecureAlgorithms.Any(a => method.Contains(a));
            }

            public float CalculateSecurityScore()
            {
                return _totalImplementations == 0 ? 0 :
                    _secureImplementations / (float)_totalImplementations;
            }
        }

        private class ErrorHandlingVisitor : DepthFirstAstVisitor
        {
            private int _totalErrorHandlers = 0;
            private int _robustHandlers = 0;

            public override void VisitTryCatchStatement(TryCatchStatement tryCatch)
            {
                _totalErrorHandlers++;
                if (IsRobustErrorHandling(tryCatch))
                {
                    _robustHandlers++;
                }
                base.VisitTryCatchStatement(tryCatch);
            }

            private bool IsRobustErrorHandling(TryCatchStatement tryCatch)
            {
                return tryCatch.CatchClauses.Count > 0 &&
                       !tryCatch.ToString().Contains("catch{}") &&
                       tryCatch.ToString().Contains("log");
            }

            public float CalculateRobustnessScore()
            {
                return _totalErrorHandlers == 0 ? 0 :
                    _robustHandlers / (float)_totalErrorHandlers;
            }
        }

        private class SecurityControlVisitor : DepthFirstAstVisitor
        {
            private Dictionary<string, int> _controlDistribution = new Dictionary<string, int>();
            private readonly HashSet<string> _securityControls = new HashSet<string> {
                "authenticate", "authorize", "validate", "verify", "encrypt",
                "decrypt", "hash", "sanitize", "escape", "filter"
            };

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                var controlType = GetSecurityControlType(methodDeclaration);
                if (controlType != null)
                {
                    _controlDistribution[controlType] =
                        _controlDistribution.GetValueOrDefault(controlType) + 1;
                }
                base.VisitMethodDeclaration(methodDeclaration);
            }

            private string GetSecurityControlType(MethodDeclaration method)
            {
                var name = method.Name.ToLower();
                return _securityControls.FirstOrDefault(c => name.Contains(c));
            }

            public float CalculateDistributionScore()
            {
                if (!_controlDistribution.Any()) return 0;
                float evenDistribution = 1.0f / (float)_securityControls.Count;
                float actualDistribution = (float)_controlDistribution.Values.Average() /
                    _controlDistribution.Values.Max();
                return (float)(actualDistribution / evenDistribution);
            }
        }

        private class ConfigurationSecurityVisitor : DepthFirstAstVisitor
        {
            private int _secureConfigs = 0;
            private int _totalConfigs = 0;

            public override void VisitSimpleType(SimpleType type)
            {
                if (IsConfigurationType(type))
                {
                    _totalConfigs++;
                    if (HasSecureConfiguration(type))
                    {
                        _secureConfigs++;
                    }
                }
                base.VisitSimpleType(type);
            }

            private bool IsConfigurationType(SimpleType type)
            {
                var name = type.ToString().ToLower();
                return name.Contains("config") ||
                       name.Contains("setting") ||
                       name.Contains("option");
            }

            private bool HasSecureConfiguration(SimpleType type)
            {
                var context = type.Parent?.ToString().ToLower() ?? "";
                return context.Contains("secure") ||
                       context.Contains("encrypt") ||
                       context.Contains("protect");
            }

            public float CalculateSecurityScore()
            {
                return _totalConfigs == 0 ? 0 :
                    _secureConfigs / (float)_totalConfigs;
            }
        }

        private class CrossPatternVisitor : DepthFirstAstVisitor
        {
            private HashSet<string> _integratedPatterns = new HashSet<string>();
            private int _totalPatterns = 0;

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                var patterns = DetectSecurityPatterns(methodDeclaration);
                if (patterns.Count > 1)
                {
                    _integratedPatterns.UnionWith(patterns);
                }
                _totalPatterns += patterns.Count;
                base.VisitMethodDeclaration(methodDeclaration);
            }

            private HashSet<string> DetectSecurityPatterns(MethodDeclaration method)
            {
                var patterns = new HashSet<string>();
                var body = method.ToString().ToLower();

                if (body.Contains("auth")) patterns.Add("authentication");
                if (body.Contains("valid")) patterns.Add("validation");
                if (body.Contains("crypt")) patterns.Add("cryptography");
                if (body.Contains("error")) patterns.Add("errorhandling");

                return patterns;
            }

            public float CalculateIntegrationScore()
            {
                return _totalPatterns == 0 ? 0 :
                    _integratedPatterns.Count / (float)_totalPatterns;
            }
        }

        private class PatternMaintenanceVisitor : DepthFirstAstVisitor
        {
            private int _wellMaintainedPatterns = 0;
            private int _totalPatterns = 0;

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                if (IsSecurityPattern(methodDeclaration))
                {
                    _totalPatterns++;
                    if (IsWellMaintained(methodDeclaration))
                    {
                        _wellMaintainedPatterns++;
                    }
                }
                base.VisitMethodDeclaration(methodDeclaration);
            }

            private bool IsSecurityPattern(MethodDeclaration method)
            {
                var name = method.Name.ToLower();
                return name.Contains("security") ||
                       name.Contains("auth") ||
                       name.Contains("valid") ||
                       name.Contains("crypt");
            }

            private bool IsWellMaintained(MethodDeclaration method)
            {
                // Changed from Documentation property to checking for XML comments
                bool hasMethodDocs = method.GetChildrenByRole(Roles.Comment).Any();
                bool hasParameterDocs = method.Parameters.All(p =>
                    p.GetChildrenByRole(Roles.Comment).Any());

                return hasMethodDocs && hasParameterDocs && !ContainsDeprecatedPatterns(method);
            }

            private bool ContainsDeprecatedPatterns(MethodDeclaration method)
            {
                var body = method.ToString().ToLower();
                return body.Contains("md5") ||
                       body.Contains("des") ||
                       body.Contains("rc4") ||
                       body.Contains("sha1");
            }

            public float CalculateMaintenanceScore()
            {
                return _totalPatterns == 0 ? 0 :
                    _wellMaintainedPatterns / (float)_totalPatterns;
            }
        }

        // Original SecurityPattern and AnalysisResult classes remain unchanged
        public class SecurityPattern
        {
            public string PatternType { get; set; }
            public string Description { get; set; }
            public float RiskScore { get; set; }
            public string Location { get; set; }
            public int LineNumber { get; set; }
            public string CodeSnippet { get; set; }
            public Dictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
            public List<string> Recommendations { get; set; } = new List<string>();
            public bool IsSafeImplementation { get; set; }
            public string Context { get; set; }
        }

        public class AnalysisResult
        {
            public List<SecurityPattern> AuthenticationPatterns { get; set; } = new List<SecurityPattern>();
            public List<SecurityPattern> ValidationPatterns { get; set; } = new List<SecurityPattern>();
            public List<SecurityPattern> CryptographyPatterns { get; set; } = new List<SecurityPattern>();
            public List<SecurityPattern> ErrorHandlingPatterns { get; set; } = new List<SecurityPattern>();
            public List<SecurityPattern> ConfigurationPatterns { get; set; } = new List<SecurityPattern>();
            public Dictionary<string, float> RiskScores { get; set; } = new Dictionary<string, float>();
        }

        // Original analysis methods remain unchanged
        public AnalysisResult AnalyzePatterns()
        {
            var visitor = new SecurityPatternVisitor(this);
            _syntaxTree.AcceptVisitor(visitor);

            var result = new AnalysisResult();

            // Process authentication patterns
            result.AuthenticationPatterns.AddRange(visitor.GetAuthenticationPatterns());

            // Process validation patterns
            result.ValidationPatterns.AddRange(visitor.GetValidationPatterns());

            // Process cryptography patterns
            result.CryptographyPatterns.AddRange(visitor.GetCryptographyPatterns());

            // Process error handling patterns
            result.ErrorHandlingPatterns.AddRange(visitor.GetErrorHandlingPatterns());

            // Process configuration patterns
            result.ConfigurationPatterns.AddRange(visitor.GetConfigurationPatterns());

            // Calculate risk scores
            foreach (var pattern in visitor.GetAllPatterns())
            {
                result.RiskScores[pattern.PatternType] = CalculatePatternRisk(pattern);
            }

            return result;
        }

        private float CalculatePatternRisk(SecurityPattern pattern)
        {
            float risk = 0.5f; // Base risk

            // Increase risk for unsafe implementations
            if (!pattern.IsSafeImplementation)
                risk += 0.3f;

            // Adjust risk based on pattern type
            switch (pattern.PatternType.ToLower())
            {
                case "authentication":
                    risk *= 1.5f; // Authentication issues are high risk
                    break;
                case "cryptography":
                    risk *= 1.4f; // Crypto issues are high risk
                    break;
                case "validation":
                    risk *= 1.2f; // Validation issues are medium-high risk
                    break;
                case "errorhandling":
                    risk *= 1.1f; // Error handling issues are medium risk
                    break;
            }

            // Adjust for recommendations
            risk += pattern.Recommendations.Count * 0.1f;

            return Math.Min(1.0f, risk);
        }

        private class SecurityPatternVisitor : DepthFirstAstVisitor
        {
            private readonly SecurityPatternAnalyzer _analyzer;
            private readonly List<SecurityPattern> _authPatterns = new List<SecurityPattern>();
            private readonly List<SecurityPattern> _validationPatterns = new List<SecurityPattern>();
            private readonly List<SecurityPattern> _cryptoPatterns = new List<SecurityPattern>();
            private readonly List<SecurityPattern> _errorPatterns = new List<SecurityPattern>();
            private readonly List<SecurityPattern> _configPatterns = new List<SecurityPattern>();

            public SecurityPatternVisitor(SecurityPatternAnalyzer analyzer)
            {
                _analyzer = analyzer;
            }

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                // Check for authentication patterns
                if (IsAuthenticationMethod(methodDeclaration))
                {
                    _authPatterns.Add(CreateAuthenticationPattern(methodDeclaration));
                }

                // Check for validation patterns
                if (IsValidationMethod(methodDeclaration))
                {
                    _validationPatterns.Add(CreateValidationPattern(methodDeclaration));
                }

                base.VisitMethodDeclaration(methodDeclaration);
            }

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                // Check for cryptographic operations
                if (IsCryptographicOperation(invocation))
                {
                    _cryptoPatterns.Add(CreateCryptoPattern(invocation));
                }

                // Check for error handling
                if (IsErrorHandling(invocation))
                {
                    _errorPatterns.Add(CreateErrorHandlingPattern(invocation));
                }

                base.VisitInvocationExpression(invocation);
            }

            private bool IsAuthenticationMethod(MethodDeclaration method)
            {
                var name = method.Name.ToLower();
                return name.Contains("auth") ||
                       name.Contains("login") ||
                       name.Contains("signin") ||
                       name.Contains("authenticate") ||
                       name.Contains("validate") ||
                       HasAuthenticationAttributes(method);
            }

            private bool IsValidationMethod(MethodDeclaration method)
            {
                var name = method.Name.ToLower();
                return name.Contains("validate") ||
                       name.Contains("verify") ||
                       name.Contains("check") ||
                       name.Contains("sanitize") ||
                       HasValidationAttributes(method);
            }

            private bool IsCryptographicOperation(InvocationExpression invocation)
            {
                var methodName = invocation.ToString().ToLower();
                return methodName.Contains("encrypt") ||
                       methodName.Contains("decrypt") ||
                       methodName.Contains("hash") ||
                       methodName.Contains("hmac") ||
                       methodName.Contains("sign") ||
                       methodName.Contains("verify");
            }

            private bool IsErrorHandling(InvocationExpression invocation)
            {
                var methodName = invocation.ToString().ToLower();
                return methodName.Contains("catch") ||
                       methodName.Contains("throw") ||
                       methodName.Contains("log") ||
                       methodName.Contains("handle");
            }

            private bool HasAuthenticationAttributes(MethodDeclaration method)
            {
                return method.Attributes.Any(attr =>
                    attr.ToString().Contains("Authorize") ||
                    attr.ToString().Contains("Authentication") ||
                    attr.ToString().Contains("Security"));
            }

            private bool HasValidationAttributes(MethodDeclaration method)
            {
                return method.Attributes.Any(attr =>
                    attr.ToString().Contains("Validate") ||
                    attr.ToString().Contains("Required") ||
                    attr.ToString().Contains("RegularExpression"));
            }

            private SecurityPattern CreateAuthenticationPattern(MethodDeclaration method)
            {
                var pattern = new SecurityPattern
                {
                    PatternType = "Authentication",
                    Description = "Authentication-related method detected",
                    Location = method.ToString(),
                    LineNumber = GetLineNumber(method),
                    CodeSnippet = GetMethodSnippet(method),
                    Context = GetContext(method)
                };

                pattern.IsSafeImplementation = CheckAuthenticationSafety(method);
                pattern.Recommendations.AddRange(GenerateAuthRecommendations(method));
                pattern.Properties["AuthType"] = DetermineAuthType(method);

                return pattern;
            }

            private SecurityPattern CreateValidationPattern(MethodDeclaration method)
            {
                var pattern = new SecurityPattern
                {
                    PatternType = "Validation",
                    Description = "Input validation method detected",
                    Location = method.ToString(),
                    LineNumber = GetLineNumber(method),
                    CodeSnippet = GetMethodSnippet(method),
                    Context = GetContext(method)
                };

                pattern.IsSafeImplementation = CheckValidationSafety(method);
                pattern.Recommendations.AddRange(GenerateValidationRecommendations(method));
                pattern.Properties["ValidationType"] = DetermineValidationType(method);

                return pattern;
            }

            private SecurityPattern CreateCryptoPattern(InvocationExpression invocation)
            {
                var pattern = new SecurityPattern
                {
                    PatternType = "Cryptography",
                    Description = "Cryptographic operation detected",
                    Location = invocation.ToString(),
                    LineNumber = GetLineNumber(invocation),
                    CodeSnippet = GetInvocationSnippet(invocation),
                    Context = GetContext(invocation)
                };

                pattern.IsSafeImplementation = CheckCryptoSafety(invocation);
                pattern.Recommendations.AddRange(GenerateCryptoRecommendations(invocation));
                pattern.Properties["CryptoType"] = DetermineCryptoType(invocation);

                return pattern;
            }

            private SecurityPattern CreateErrorHandlingPattern(InvocationExpression invocation)
            {
                var pattern = new SecurityPattern
                {
                    PatternType = "ErrorHandling",
                    Description = "Error handling operation detected",
                    Location = invocation.ToString(),
                    LineNumber = GetLineNumber(invocation),
                    CodeSnippet = GetInvocationSnippet(invocation),
                    Context = GetContext(invocation)
                };

                pattern.IsSafeImplementation = CheckErrorHandlingSafety(invocation);
                pattern.Recommendations.AddRange(GenerateErrorHandlingRecommendations(invocation));
                pattern.Properties["HandlingType"] = DetermineErrorHandlingType(invocation);

                return pattern;
            }

            public List<SecurityPattern> GetAuthenticationPatterns() => _authPatterns;
            public List<SecurityPattern> GetValidationPatterns() => _validationPatterns;
            public List<SecurityPattern> GetCryptographyPatterns() => _cryptoPatterns;
            public List<SecurityPattern> GetErrorHandlingPatterns() => _errorPatterns;
            public List<SecurityPattern> GetConfigurationPatterns() => _configPatterns;

            public IEnumerable<SecurityPattern> GetAllPatterns()
            {
                return _authPatterns
                    .Concat(_validationPatterns)
                    .Concat(_cryptoPatterns)
                    .Concat(_errorPatterns)
                    .Concat(_configPatterns);
            }

            private bool CheckAuthenticationSafety(MethodDeclaration method)
            {
                var body = method.ToString().ToLower();
                return !body.Contains("plaintext") &&
                       body.Contains("hash") &&
                       !body.Contains("md5") &&
                       body.Contains("salt");
            }

            private bool CheckValidationSafety(MethodDeclaration method)
            {
                var body = method.ToString().ToLower();
                return body.Contains("try") &&
                       body.Contains("catch") &&
                       !body.Contains("catch{}") &&
                       body.Contains("if");
            }

            private bool CheckCryptoSafety(InvocationExpression invocation)
            {
                var expr = invocation.ToString().ToLower();
                return !expr.Contains("md5") &&
                       !expr.Contains("des") &&
                       !expr.Contains("rc2") &&
                       (expr.Contains("aes") || expr.Contains("sha256") || expr.Contains("sha512"));
            }

            private bool CheckErrorHandlingSafety(InvocationExpression invocation)
            {
                var expr = invocation.ToString().ToLower();
                return !expr.Contains("empty catch") &&
                       !expr.Contains("catch{}") &&
                       expr.Contains("log");
            }

            private string DetermineAuthType(MethodDeclaration method)
            {
                var body = method.ToString().ToLower();
                if (body.Contains("jwt")) return "JWT";
                if (body.Contains("oauth")) return "OAuth";
                if (body.Contains("basic")) return "Basic";
                if (body.Contains("digest")) return "Digest";
                return "Custom";
            }

            private string DetermineValidationType(MethodDeclaration method)
            {
                var body = method.ToString().ToLower();
                if (body.Contains("regex")) return "RegEx";
                if (body.Contains("range")) return "Range";
                if (body.Contains("length")) return "Length";
                if (body.Contains("type")) return "Type";
                return "Custom";
            }

            private string DetermineCryptoType(InvocationExpression invocation)
            {
                var expr = invocation.ToString().ToLower();
                if (expr.Contains("aes")) return "AES";
                if (expr.Contains("rsa")) return "RSA";
                if (expr.Contains("sha")) return "SHA";
                if (expr.Contains("hmac")) return "HMAC";
                return "Custom";
            }

            private string DetermineErrorHandlingType(InvocationExpression invocation)
            {
                var expr = invocation.ToString().ToLower();
                if (expr.Contains("exception")) return "Exception";
                if (expr.Contains("error")) return "Error";
                if (expr.Contains("log")) return "Logging";
                if (expr.Contains("handle")) return "Handler";
                return "Custom";
            }

            private List<string> GenerateAuthRecommendations(MethodDeclaration method)
            {
                var recommendations = new List<string>();
                var body = method.ToString().ToLower();

                if (!body.Contains("hash"))
                    recommendations.Add("Implement password hashing");
                if (!body.Contains("salt"))
                    recommendations.Add("Add password salting");
                if (body.Contains("md5"))
                    recommendations.Add("Replace MD5 with a secure hashing algorithm");

                return recommendations;
            }

            private List<string> GenerateValidationRecommendations(MethodDeclaration method)
            {
                var recommendations = new List<string>();
                var body = method.ToString().ToLower();

                if (!body.Contains("try"))
                    recommendations.Add("Add exception handling");
                if (!body.Contains("sanitize"))
                    recommendations.Add("Implement input sanitization");
                if (!body.Contains("whitelist"))
                    recommendations.Add("Consider using a whitelist approach");

                return recommendations;
            }

            private List<string> GenerateCryptoRecommendations(InvocationExpression invocation)
            {
                var recommendations = new List<string>();
                var expr = invocation.ToString().ToLower();

                if (expr.Contains("md5"))
                    recommendations.Add("Replace MD5 with SHA-256 or stronger");
                if (expr.Contains("des"))
                    recommendations.Add("Replace DES with AES");
                if (!expr.Contains("salt"))
                    recommendations.Add("Add cryptographic salt");

                return recommendations;
            }

            private List<string> GenerateErrorHandlingRecommendations(InvocationExpression invocation)
            {
                var recommendations = new List<string>();
                var expr = invocation.ToString().ToLower();

                if (!expr.Contains("log"))
                    recommendations.Add("Add error logging");
                if (expr.Contains("catch{}"))
                    recommendations.Add("Implement proper error handling in catch blocks");
                if (!expr.Contains("specific"))
                    recommendations.Add("Use specific exception types");

                return recommendations;
            }

            private int GetLineNumber(AstNode node)
            {
                return node.StartLocation.Line;
            }

            private string GetMethodSnippet(MethodDeclaration method)
            {
                var startLine = method.StartLocation.Line;
                var endLine = method.EndLocation.Line;
                var lines = _analyzer._code.Split('\n');

                if (startLine <= 0 || endLine >= lines.Length) return "";

                return string.Join("\n",
                    lines.Skip(startLine - 1)
                         .Take(endLine - startLine + 1));
            }

            private string GetInvocationSnippet(InvocationExpression invocation)
            {
                var line = invocation.StartLocation.Line;
                var lines = _analyzer._code.Split('\n');

                if (line <= 0 || line > lines.Length) return "";

                return lines[line - 1].Trim();
            }

            private string GetContext(AstNode node)
            {
                var line = node.StartLocation.Line;
                var lines = _analyzer._code.Split('\n');

                if (line <= 0 || line > lines.Length) return "";

                var contextStart = Math.Max(0, line - 3);
                var contextLength = Math.Min(5, lines.Length - contextStart);

                return string.Join("\n",
                    lines.Skip(contextStart)
                         .Take(contextLength));
            }
        }
    }
}
