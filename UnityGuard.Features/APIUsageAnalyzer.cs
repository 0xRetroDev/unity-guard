using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.TypeSystem;

namespace RetroDev.UnityGuard.UnityGuard.Features
{
    public class APIUsageAnalyzer
    {
        private readonly SyntaxTree _syntaxTree;
        private readonly string _code;

        public APIUsageAnalyzer(SyntaxTree syntaxTree, string code)
        {
            _syntaxTree = syntaxTree;
            _code = code;
        }

        public float[] AnalyzeAPIUsage()
        {
            var metrics = new float[20];

            // 1. Network API Usage
            metrics[0] = AnalyzeNetworkAPIs();

            // 2. File System Operations
            metrics[1] = AnalyzeFileSystemAPIs();

            // 3. Cryptographic API Usage
            metrics[2] = AnalyzeCryptoAPIs();

            // 4. Authentication APIs
            metrics[3] = AnalyzeAuthAPIs();

            // 5. Unity-Specific APIs
            metrics[4] = AnalyzeUnityAPIs();

            // 6. Serialization APIs
            metrics[5] = AnalyzeSerializationAPIs();

            // 7. Database Access
            metrics[6] = AnalyzeDatabaseAPIs();

            // 8. Command Execution
            metrics[7] = AnalyzeCommandExecutionAPIs();

            // 9. Memory Management
            metrics[8] = AnalyzeMemoryAPIs();

            // 10. Input Handling
            metrics[9] = AnalyzeInputAPIs();

            // 11. Reflection Usage
            metrics[10] = AnalyzeReflectionAPIs();

            // 12. Platform Invoke
            metrics[11] = AnalyzePInvokeAPIs();

            // 13. IPC Communications
            metrics[12] = AnalyzeIPCAPIs();

            // 14. Resource Management
            metrics[13] = AnalyzeResourceAPIs();

            // 15. Logging APIs
            metrics[14] = AnalyzeLoggingAPIs();

            // 16. Asset Management
            metrics[15] = AnalyzeResourceAPIs();

            // 17. Threading/Async
            metrics[16] = AnalyzeThreadingAPIs();

            // 18. Unity Network Gaming
            metrics[17] = AnalyzeNetworkGamingAPIs();

            // 19. Unity UI
            metrics[18] = AnalyzeUIAPIs();

            // 20. Plugin Integration
            metrics[19] = AnalyzePluginAPIs();

            return metrics;
        }


        private float AnalyzeNetworkAPIs()
        {
            var visitor = new NetworkAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.NetworkUsageScore);
        }

        private float AnalyzeFileSystemAPIs()
        {
            var visitor = new FileSystemAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.FileSystemUsageScore);
        }

        private float AnalyzeCryptoAPIs()
        {
            var visitor = new CryptoAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.CryptoUsageScore);
        }

        private float AnalyzeAuthAPIs()
        {
            var visitor = new AuthenticationAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.AuthUsageScore);
        }

        private float AnalyzeUnityAPIs()
        {
            var visitor = new UnityAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.UnityUsageScore);
        }

        private float AnalyzeSerializationAPIs()
        {
            var visitor = new SerializationAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.SerializationUsageScore);
        }

        private float AnalyzeDatabaseAPIs()
        {
            var visitor = new DatabaseAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.DatabaseUsageScore);
        }

        private float AnalyzeCommandExecutionAPIs()
        {
            var visitor = new CommandExecutionAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.CommandUsageScore);
        }

        private float AnalyzeMemoryAPIs()
        {
            var visitor = new MemoryAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.MemoryUsageScore);
        }

        private float AnalyzeInputAPIs()
        {
            var visitor = new InputAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.InputUsageScore);
        }

        private float AnalyzeReflectionAPIs()
        {
            var visitor = new ReflectionAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.ReflectionUsageScore);
        }

        private float AnalyzePInvokeAPIs()
        {
            var visitor = new PInvokeAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.PInvokeUsageScore);
        }

        private float AnalyzeIPCAPIs()
        {
            var visitor = new IPCAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.IPCUsageScore);
        }

        private float AnalyzeResourceAPIs()
        {
            var visitor = new ResourceAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.ResourceUsageScore);
        }

        private float AnalyzeLoggingAPIs()
        {
            var visitor = new LoggingAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.LoggingUsageScore);
        }

        private float AnalyzeThreadingAPIs()
        {
            var visitor = new ThreadingAPIVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.ThreadingUsageScore);
        }

        private float AnalyzeNetworkGamingAPIs()
        {
            var visitor = new UnityAPIVisitor(); // We can reuse Unity visitor and focus on networking
            _syntaxTree.AcceptVisitor(visitor);

            // Focus on networking-specific score
            float score = visitor.UnityUsageScore;
            if (score > 0)
            {
                // If we find network-related Unity APIs, weight them higher
                var networkPatterns = new[] { "NetworkBehaviour", "NetworkManager", "Mirror", "Photon" };
                if (networkPatterns.Any(p => _code.Contains(p)))
                {
                    score *= 1.5f;
                }
            }
            return NormalizeMetric(score);
        }

        private float AnalyzeUIAPIs()
        {
            var visitor = new UnityAPIVisitor(); // We can reuse Unity visitor
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.UnityUsageScore);
        }

        private float AnalyzePluginAPIs()
        {
            var visitor = new UnityAPIVisitor(); // We can reuse Unity visitor
            _syntaxTree.AcceptVisitor(visitor);
            var score = visitor.UnityUsageScore;

            // Check for plugin-specific patterns
            if (_code.Contains("Plugin") || _code.Contains("Editor") || _code.Contains("CustomEditor"))
            {
                score *= (int)1.2f;
            }
            return NormalizeMetric(score);
        }

        private float NormalizeMetric(float value)
        {
            const float MAX_SCORE = 100.0f;
            return Math.Min(value / MAX_SCORE, 1.0f);
        }


        private class CryptoAPIVisitor : DepthFirstAstVisitor
        {
            public int CryptoUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _cryptoAPIs = new Dictionary<string, int>
    {
        // Weak/Obsolete Crypto (Higher scores = more risky)
        {"MD5", 5},
        {"SHA1", 4},
        {"DES", 5},
        {"RC2", 5},
        
        // Recommended Crypto
        {"SHA256", 1},
        {"SHA512", 1},
        {"AES", 1},
        {"RSA", 2},
        
        // Crypto Operations
        {"Encrypt", 2},
        {"Decrypt", 2},
        {"GenerateKey", 2},
        {"CreateEncryptor", 2},
        {"CreateDecryptor", 2},
        
        // Random Number Generation
        {"Random", 4},  // System.Random (not cryptographically secure)
        {"RNGCryptoServiceProvider", 1},
        {"RandomNumberGenerator", 1}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _cryptoAPIs)
                    {
                        if (mre.MemberName.Contains(api.Key))
                        {
                            CryptoUsageScore += api.Value;
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }
        }

        private class AuthenticationAPIVisitor : DepthFirstAstVisitor
        {
            public int AuthUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _authAPIs = new Dictionary<string, int>
    {
        // Authentication Methods
        {"Authenticate", 3},
        {"Login", 3},
        {"SignIn", 3},
        {"Verify", 3},
        {"Validate", 3},
        
        // Token Handling
        {"GenerateToken", 3},
        {"ValidateToken", 3},
        {"JwtSecurityToken", 2},
        {"OAuth", 2},
        
        // Password Operations
        {"VerifyPassword", 3},
        {"HashPassword", 2},
        {"CheckPassword", 3},
        
        // Session Management
        {"Session", 2},
        {"Cookie", 2}
    };

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                foreach (var api in _authAPIs)
                {
                    if (methodDeclaration.Name.Contains(api.Key))
                    {
                        AuthUsageScore += api.Value;
                    }
                }
                base.VisitMethodDeclaration(methodDeclaration);
            }
        }

        private class UnityAPIVisitor : DepthFirstAstVisitor
        {
            public int UnityUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _unityAPIs = new Dictionary<string, int>
    {
        // PlayerPrefs (potential security concerns)
        {"PlayerPrefs.Set", 3},
        {"PlayerPrefs.Get", 2},
        
        // Network Related
        {"NetworkManager", 3},
        {"NetworkBehaviour", 2},
        {"Mirror", 2},
        {"Photon", 2},
        
        // Web Requests
        {"UnityWebRequest", 3},
        {"WWW", 4},  // Deprecated
        
        // File Operations
        {"Resources.Load", 2},
        {"AssetBundle", 2},
        
        // Command Execution
        {"ExecuteInEditMode", 3},
        {"RuntimeInitializeOnLoadMethod", 3}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _unityAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            UnityUsageScore += api.Value;
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }
        }

        private class SerializationAPIVisitor : DepthFirstAstVisitor
        {
            public int SerializationUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _serializationAPIs = new Dictionary<string, int>
    {
        // High Risk APIs
        {"BinaryFormatter", 5},
        {"JavaScriptSerializer", 4},
        {"DataContractSerializer", 3},
        
        // JSON Related
        {"JsonSerializer", 2},
        {"JsonConvert", 2},
        {"FromJson", 2},
        {"ToJson", 2},
        
        // XML Related
        {"XmlSerializer", 3},
        {"XDocument", 2},
        {"XmlDocument", 3},
        
        // Unity Specific
        {"JsonUtility", 2},
        {"ScriptableObject", 2}
    };

            public override void VisitObjectCreateExpression(ObjectCreateExpression objectCreateExpression)
            {
                foreach (var api in _serializationAPIs)
                {
                    if (objectCreateExpression.Type.ToString().Contains(api.Key))
                    {
                        SerializationUsageScore += api.Value;
                    }
                }
                base.VisitObjectCreateExpression(objectCreateExpression);
            }
        }

        private class DatabaseAPIVisitor : DepthFirstAstVisitor
        {
            public int DatabaseUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _dbAPIs = new Dictionary<string, int>
    {
        // SQL Related
        {"SqlCommand", 4},
        {"SqlConnection", 3},
        {"ExecuteNonQuery", 4},
        {"ExecuteReader", 3},
        
        // ORM Related
        {"DbContext", 2},
        {"Entity", 2},
        {"Repository", 2},
        
        // Unity PlayerPrefs
        {"PlayerPrefs", 3},
        
        // Raw Queries
        {"ExecuteQuery", 4},
        {"RawQuery", 5}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _dbAPIs)
                    {
                        if (mre.MemberName.Contains(api.Key))
                        {
                            DatabaseUsageScore += api.Value;

                            // Check for SQL injection risks
                            if (ContainsSqlInjectionRisk(invocationExpression))
                            {
                                DatabaseUsageScore += 5;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private bool ContainsSqlInjectionRisk(InvocationExpression expr)
            {
                // Check for string concatenation in SQL
                return expr.ToString().Contains("\"SELECT") ||
                       expr.ToString().Contains("\"INSERT") ||
                       expr.ToString().Contains("\"UPDATE") ||
                       expr.ToString().Contains("\"DELETE") ||
                       expr.ToString().Contains(" + ") ||
                       expr.ToString().Contains("string.Concat");
            }
        }

        private class CommandExecutionAPIVisitor : DepthFirstAstVisitor
        {
            public int CommandUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _commandAPIs = new Dictionary<string, int>
    {
        // Process/Shell Execution
        {"Process.Start", 5},
        {"ProcessStartInfo", 4},
        {"Shell.Execute", 5},
        {"cmd.exe", 5},
        {"powershell", 5},
        {"bash", 5},
        
        // Code Execution
        {"Assembly.Load", 5},
        {"LoadFrom", 4},
        {"LoadFile", 4},
        
        // Reflection
        {"Invoke", 3},
        {"InvokeMember", 3},
        {"DynamicInvoke", 3}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _commandAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            CommandUsageScore += api.Value;

                            // Check for command injection risks
                            if (ContainsCommandInjectionRisk(invocationExpression))
                            {
                                CommandUsageScore += 5;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private bool ContainsCommandInjectionRisk(InvocationExpression expr)
            {
                return expr.Arguments.Any(arg =>
                    arg.ToString().Contains("userInput") ||
                    arg.ToString().Contains("args") ||
                    arg.ToString().Contains("parameter") ||
                    arg.ToString().Contains(" + ") ||
                    arg.ToString().Contains("string.Format"));
            }
        }

        private class MemoryAPIVisitor : DepthFirstAstVisitor
        {
            public int MemoryUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _memoryAPIs = new Dictionary<string, int>
    {
        // Unsafe Memory Operations
        {"unsafe", 5},
        {"fixed", 4},
        {"stackalloc", 5},
        {"Marshal", 4},
        
        // Memory Management
        {"GCHandle", 3},
        {"AllocHGlobal", 4},
        {"FreeHGlobal", 3},
        {"PtrToStructure", 4},
        
        // Unity Memory
        {"OnDestroy", 2},
        {"Dispose", 2},
        {"ClearAllPools", 2}
    };

            public override void VisitUnsafeStatement(UnsafeStatement unsafeStatement)
            {
                MemoryUsageScore += 5;
                base.VisitUnsafeStatement(unsafeStatement);
            }

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _memoryAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            MemoryUsageScore += api.Value;
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }
        }

        private class InputAPIVisitor : DepthFirstAstVisitor
        {
            public int InputUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _inputAPIs = new Dictionary<string, int>
    {
        // Unity Input
        {"Input.GetKey", 2},
        {"Input.GetButton", 2},
        {"Input.GetAxis", 2},
        {"Input.mousePosition", 2},
        
        // User Input
        {"ReadLine", 3},
        {"GetString", 3},
        {"Parse", 3},
        
        // Web Input
        {"Request.Form", 4},
        {"Request.QueryString", 4},
        {"Request.Params", 4},
        
        // File Input
        {"OpenRead", 3},
        {"ReadAllText", 3},
        {"ReadAllBytes", 3}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _inputAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            InputUsageScore += api.Value;

                            // Check for input validation
                            if (!HasInputValidation(invocationExpression))
                            {
                                InputUsageScore += 2;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private bool HasInputValidation(InvocationExpression expr)
            {
                // Look for common validation patterns
                var parentStatement = expr.GetParent<Statement>();
                if (parentStatement == null) return false;

                return parentStatement.ToString().Contains("TryParse") ||
                       parentStatement.ToString().Contains("Validate") ||
                       parentStatement.ToString().Contains("if") ||
                       parentStatement.ToString().Contains("switch");
            }
        }

        private class ReflectionAPIVisitor : DepthFirstAstVisitor
        {
            public int ReflectionUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _reflectionAPIs = new Dictionary<string, int>
    {
        // Type Information
        {"GetType", 2},
        {"TypeOf", 2},
        {"GetTypeInfo", 2},
        
        // Member Access
        {"GetMethod", 4},
        {"GetField", 4},
        {"GetProperty", 4},
        {"GetMember", 4},
        
        // Invocation
        {"Invoke", 5},
        {"InvokeMember", 5},
        {"DynamicInvoke", 5},
        
        // Assembly Loading
        {"Assembly.Load", 5},
        {"Assembly.LoadFrom", 5},
        {"Assembly.LoadFile", 5}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _reflectionAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            ReflectionUsageScore += api.Value;

                            // Check for potential risks
                            if (ContainsReflectionRisk(invocationExpression))
                            {
                                ReflectionUsageScore += 3;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            // Inside ReflectionAPIVisitor
            private bool ContainsReflectionRisk(InvocationExpression expr)
            {
                return expr.Arguments.Any(arg =>
                    arg.ToString().Contains("userInput") ||
                    arg.ToString().Contains("GetString") ||
                    arg.ToString().Contains("ReadLine") ||
                    arg.ToString().Contains("Request.") ||
                    arg.ToString().Contains("variable") ||
                    arg.ToString().Contains("dynamic"));
            }
        }

        private class PInvokeAPIVisitor : DepthFirstAstVisitor
        {
            public int PInvokeUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _pInvokeAPIs = new Dictionary<string, int>
    {
        // DllImport Attributes
        {"DllImport", 4},
        {"UnmanagedFunctionPointer", 4},
        
        // Common Windows APIs
        {"kernel32", 5},
        {"user32", 5},
        {"advapi32", 5},
        {"winmm", 4},
        
        // Marshal Operations
        {"Marshal.Copy", 3},
        {"Marshal.PtrToStructure", 4},
        {"Marshal.GetFunctionPointerForDelegate", 4}
    };

            public override void VisitAttribute(ICSharpCode.Decompiler.CSharp.Syntax.Attribute attribute)
            {
                if (attribute.Type is SimpleType simpleType && simpleType.Identifier == "DllImport")
                {
                    PInvokeUsageScore += 4;
                    // Check for unsafe DLL imports
                    if (attribute.Arguments.Count > 0)
                    {
                        var dllName = attribute.Arguments.First().ToString().ToLower();
                        foreach (var api in _pInvokeAPIs)
                        {
                            if (dllName.Contains(api.Key.ToLower()))
                            {
                                PInvokeUsageScore += api.Value;
                            }
                        }
                    }
                }
                base.VisitAttribute(attribute);
            }
        }

        private class IPCAPIVisitor : DepthFirstAstVisitor
        {
            public int IPCUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _ipcAPIs = new Dictionary<string, int>
    {
        // Named Pipes
        {"NamedPipeServerStream", 4},
        {"NamedPipeClientStream", 4},
        
        // Memory Mapped Files
        {"MemoryMappedFile", 3},
        {"CreateViewStream", 3},
        
        // Message Queues
        {"MessageQueue", 3},
        {"Send", 2},
        {"Receive", 2},
        
        // Shared Memory
        {"SharedMemory", 4},
        {"CreateSharedMemory", 4}
    };

            public override void VisitObjectCreateExpression(ObjectCreateExpression objectCreateExpression)
            {
                foreach (var api in _ipcAPIs)
                {
                    if (objectCreateExpression.Type.ToString().Contains(api.Key))
                    {
                        IPCUsageScore += api.Value;
                    }
                }
                base.VisitObjectCreateExpression(objectCreateExpression);
            }
        }

        private class ResourceAPIVisitor : DepthFirstAstVisitor
        {
            public int ResourceUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _resourceAPIs = new Dictionary<string, int>
    {
        // Unity Resources
        {"Resources.Load", 3},
        {"Resources.LoadAsync", 3},
        {"Resources.LoadAll", 4},
        
        // Asset Management
        {"AssetBundle", 3},
        {"AssetDatabase", 2},
        {"ScriptableObject", 2},
        
        // File Resources
        {"File.Open", 3},
        {"Stream", 2},
        {"using", 1}  // Resource cleanup
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _resourceAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            ResourceUsageScore += api.Value;

                            // Check for resource cleanup
                            if (!HasProperResourceCleanup(invocationExpression))
                            {
                                ResourceUsageScore += 2;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private bool HasProperResourceCleanup(InvocationExpression expr)
            {
                var parentBlock = expr.GetParent<BlockStatement>();
                if (parentBlock == null) return false;

                return parentBlock.ToString().Contains("using") ||
                       parentBlock.ToString().Contains("Dispose") ||
                       parentBlock.ToString().Contains("finally");
            }
        }

        private class LoggingAPIVisitor : DepthFirstAstVisitor
        {
            public int LoggingUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _loggingAPIs = new Dictionary<string, int>
    {
        // Unity Logging
        {"Debug.Log", 2},
        {"Debug.LogWarning", 2},
        {"Debug.LogError", 3},
        
        // Common Logging Frameworks
        {"Console.WriteLine", 2},
        {"Console.Write", 2},
        {"Trace", 2},
        {"Logger", 2},
        
        // Sensitive Information Logging
        {"Password", 5},
        {"Token", 5},
        {"Key", 5},
        {"Secret", 5}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _loggingAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            LoggingUsageScore += api.Value;

                            // Check for sensitive data logging
                            if (ContainsSensitiveDataLogging(invocationExpression))
                            {
                                LoggingUsageScore += 5;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private bool ContainsSensitiveDataLogging(InvocationExpression expr)
            {
                var logContent = expr.ToString().ToLower();
                return logContent.Contains("password") ||
                       logContent.Contains("token") ||
                       logContent.Contains("key") ||
                       logContent.Contains("secret") ||
                       logContent.Contains("credential") ||
                       logContent.Contains("auth");
            }
        }

        private class ThreadingAPIVisitor : DepthFirstAstVisitor
        {
            public int ThreadingUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _threadingAPIs = new Dictionary<string, int>
    {
        // Threading
        {"Thread", 3},
        {"ThreadPool", 3},
        {"BackgroundWorker", 2},
        
        // Tasks
        {"Task.Run", 2},
        {"Task.Factory", 2},
        {"Parallel", 3},
        
        // Synchronization
        {"lock", 2},
        {"Monitor", 3},
        {"Mutex", 3},
        {"Semaphore", 3}
    };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    foreach (var api in _threadingAPIs)
                    {
                        if (mre.ToString().Contains(api.Key))
                        {
                            ThreadingUsageScore += api.Value;

                            // Check for thread safety issues
                            if (!HasThreadSafety(invocationExpression))
                            {
                                ThreadingUsageScore += 2;
                            }
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private bool HasThreadSafety(InvocationExpression expr)
            {
                var parentBlock = expr.GetParent<BlockStatement>();
                if (parentBlock == null) return false;

                return parentBlock.ToString().Contains("lock") ||
                       parentBlock.ToString().Contains("Interlocked") ||
                       parentBlock.ToString().Contains("Monitor") ||
                       parentBlock.ToString().Contains("Mutex");
            }
        }

        private class NetworkAPIVisitor : DepthFirstAstVisitor
        {
            public int NetworkUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _networkAPIs = new Dictionary<string, int>
        {
            // Unity Network APIs
            {"UnityWebRequest", 3},
            {"WWW", 4}, // Higher score as it's deprecated and less secure
            {"NetworkClient", 2},
            {"NetworkServer", 2},
            {"NetworkManager", 2},
            
            // C# Network APIs
            {"HttpClient", 2},
            {"WebClient", 3},
            {"Socket", 4},
            {"TcpClient", 3},
            {"UdpClient", 3},
            
            // High-risk network operations
            {"DownloadFile", 4},
            {"UploadFile", 4},
            {"OpenRead", 3},
            {"OpenWrite", 3}
        };

            public override void VisitSimpleType(SimpleType simpleType)
            {
                if (_networkAPIs.TryGetValue(simpleType.Identifier, out int score))
                {
                    NetworkUsageScore += score;
                }
                base.VisitSimpleType(simpleType);
            }

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    if (_networkAPIs.TryGetValue(mre.MemberName, out int score))
                    {
                        NetworkUsageScore += score;
                    }

                    // Check for insecure protocols
                    if (mre.ToString().Contains("http://"))
                    {
                        NetworkUsageScore += 5; // Higher risk for insecure HTTP
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }
        }

        private class FileSystemAPIVisitor : DepthFirstAstVisitor
        {
            public int FileSystemUsageScore { get; private set; } = 0;

            private readonly Dictionary<string, int> _fileSystemAPIs = new Dictionary<string, int>
        {
            // Direct file operations
            {"File.Open", 3},
            {"File.Create", 3},
            {"File.Delete", 4},
            {"File.Move", 3},
            {"File.Copy", 3},
            {"File.WriteAllText", 3},
            {"File.WriteAllBytes", 3},
            {"File.ReadAllText", 2},
            {"File.ReadAllBytes", 2},
            
            // Directory operations
            {"Directory.Create", 3},
            {"Directory.Delete", 4},
            {"Directory.Move", 3},
            {"Directory.GetFiles", 2},
            
            // Stream operations
            {"FileStream", 3},
            {"StreamWriter", 3},
            {"StreamReader", 2},
            
            // Unity specific
            {"Resources.Load", 2},
            {"AssetDatabase", 2},
            {"PlayerPrefs", 2}
        };

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    string fullName = GetFullMemberName(mre);
                    if (_fileSystemAPIs.TryGetValue(fullName, out int score))
                    {
                        FileSystemUsageScore += score;

                        // Check for potential path traversal
                        var args = invocationExpression.Arguments;
                        if (args.Any(arg => ContainsPathTraversalRisk(arg)))
                        {
                            FileSystemUsageScore += 3; // Additional risk
                        }
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            private string GetFullMemberName(MemberReferenceExpression mre)
            {
                if (mre.Target is IdentifierExpression ide)
                {
                    return $"{ide.Identifier}.{mre.MemberName}";
                }
                return mre.MemberName;
            }

            private bool ContainsPathTraversalRisk(Expression arg)
            {
                // Check for path concatenation and user input
                return arg.ToString().Contains("Path.Combine") ||
                       arg.ToString().Contains("GetUserInput") ||
                       arg.ToString().Contains("CommandLine") ||
                       arg.ToString().Contains("+") || // String concatenation
                       arg.ToString().Contains("..");  // Directory traversal
            }
        }
    }
}

