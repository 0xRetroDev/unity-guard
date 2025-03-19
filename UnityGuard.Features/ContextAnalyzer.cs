using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.TypeSystem;

namespace RetroDev.UnityGuard.UnityGuard.Features
{
    public class ContextAnalyzer
    {
        private readonly SyntaxTree _syntaxTree;
        private readonly string _code;
        private readonly Dictionary<string, ContextInfo> _contextData;

        public ContextAnalyzer(SyntaxTree syntaxTree, string code)
        {
            _syntaxTree = syntaxTree;
            _code = code;
            _contextData = new Dictionary<string, ContextInfo>();
        }

        public class ContextInfo
        {
            public string Name { get; set; }
            public string Type { get; set; }
            public string Scope { get; set; }
            public int Complexity { get; set; }
            public List<string> Dependencies { get; set; } = new List<string>();
            public HashSet<string> RelatedMethods { get; set; } = new HashSet<string>();
            public string Namespace { get; set; }
            public bool IsSecurityRelated { get; set; }
            public int LineNumber { get; set; }
            public string CodeBlock { get; set; }
        }

        public float[] AnalyzeContextMetrics()
        {
            var visitor = new ContextVisitor(this);
            _syntaxTree.AcceptVisitor(visitor);

            var metrics = new float[20];

            // 1. Code Block Relationships
            metrics[0] = AnalyzeCodeRelationships();

            // 2. Security Context Density
            metrics[1] = AnalyzeSecurityContextDensity();

            // 3. Method Coupling
            metrics[2] = AnalyzeMethodCoupling();

            // 4. Namespace Organization
            metrics[3] = AnalyzeNamespaceOrganization();

            // 5. Error Handling Context
            metrics[4] = AnalyzeErrorHandlingContext();

            // 6. Security Pattern Context
            metrics[5] = AnalyzeSecurityPatternContext();

            // 7. Variable Usage Context
            metrics[6] = AnalyzeVariableUsageContext();

            // 8. Method Complexity Context
            metrics[7] = AnalyzeMethodComplexityContext();

            // 9. Control Flow Context
            metrics[8] = AnalyzeControlFlowContext();

            // 10. Data Flow Context
            metrics[9] = AnalyzeDataFlowContext();

            // 11. Exception Context
            metrics[10] = AnalyzeExceptionContext();

            // 12. Resource Usage Context
            metrics[11] = AnalyzeResourceContext();

            // 13. Threading Context
            metrics[12] = AnalyzeThreadingContext();

            // 14. Security Boundary Context
            metrics[13] = AnalyzeSecurityBoundaryContext();

            // 15. Input Validation Context
            metrics[14] = AnalyzeInputValidationContext();

            // 16. Output Encoding Context
            metrics[15] = AnalyzeOutputEncodingContext();

            // 17. Authentication Context
            metrics[16] = AnalyzeAuthenticationContext();

            // 18. Authorization Context
            metrics[17] = AnalyzeAuthorizationContext();

            // 19. Logging Context
            metrics[18] = AnalyzeLoggingContext();

            // 20. Overall Context Score
            metrics[19] = CalculateOverallContextScore();

            return metrics;
        }

        private class ContextVisitor : DepthFirstAstVisitor
        {
            private readonly ContextAnalyzer _analyzer;
            private readonly Stack<string> _currentContext = new Stack<string>();
            private int _currentComplexity;

            public ContextVisitor(ContextAnalyzer analyzer)
            {
                _analyzer = analyzer;
            }

            private void CountComplexity(MethodDeclaration method)
            {
                var complexityVisitor = new ComplexityVisitor();
                method.AcceptVisitor(complexityVisitor);
                _currentComplexity = complexityVisitor.Complexity;
            }

            public override void VisitMethodDeclaration(MethodDeclaration methodDecl)
            {
                var context = new ContextInfo
                {
                    Name = methodDecl.Name,
                    Type = "Method",
                    Scope = GetMethodScope(methodDecl),
                    LineNumber = methodDecl.StartLocation.Line,
                    CodeBlock = GetMethodBlock(methodDecl),
                    IsSecurityRelated = IsSecurityRelatedMethod(methodDecl)
                };

                _currentContext.Push(methodDecl.Name);
                CountComplexity(methodDecl);

                AnalyzeMethodContext(methodDecl, context);
                context.Complexity = _currentComplexity;

                _analyzer._contextData[methodDecl.Name] = context;
                base.VisitMethodDeclaration(methodDecl);

                _currentContext.Pop();
            }

            public override void VisitForStatement(ForStatement forStatement)
            {
                _currentComplexity++;
                base.VisitForStatement(forStatement);
            }

            public override void VisitWhileStatement(WhileStatement whileStatement)
            {
                _currentComplexity++;
                base.VisitWhileStatement(whileStatement);
            }

            public override void VisitTryCatchStatement(TryCatchStatement tryCatchStatement)
            {
                _currentComplexity++;
                base.VisitTryCatchStatement(tryCatchStatement);
            }

            private string GetMethodScope(MethodDeclaration method)
            {
                if (method.Modifiers.HasFlag(Modifiers.Public)) return "Public";
                if (method.Modifiers.HasFlag(Modifiers.Private)) return "Private";
                if (method.Modifiers.HasFlag(Modifiers.Protected)) return "Protected";
                if (method.Modifiers.HasFlag(Modifiers.Internal)) return "Internal";
                return "Default";
            }

            private string GetMethodBlock(MethodDeclaration method)
            {
                var startLine = method.StartLocation.Line;
                var endLine = method.EndLocation.Line;
                var lines = _analyzer._code.Split('\n');

                if (startLine <= 0 || endLine >= lines.Length) return "";

                return string.Join("\n",
                    lines.Skip(startLine - 1)
                         .Take(endLine - startLine + 1));
            }

            private bool IsSecurityRelatedMethod(MethodDeclaration method)
            {
                var securityKeywords = new[]
                {
                    "security", "auth", "crypt", "hash", "password", "token",
                    "verify", "validate", "permission", "role", "user", "access"
                };

                return securityKeywords.Any(keyword =>
                    method.Name.ToLower().Contains(keyword) ||
                    method.ToString().ToLower().Contains(keyword));
            }

            private void AnalyzeMethodContext(MethodDeclaration method, ContextInfo context)
            {
                // Analyze dependencies
                var dependencyVisitor = new DependencyVisitor();
                method.AcceptVisitor(dependencyVisitor);
                context.Dependencies = dependencyVisitor.Dependencies;

                // Analyze related methods
                var calledMethods = new CallGraphVisitor();
                method.AcceptVisitor(calledMethods);
                context.RelatedMethods = calledMethods.CalledMethods;

                // Get namespace
                var namespaceDecl = method.Ancestors.OfType<NamespaceDeclaration>().FirstOrDefault();
                context.Namespace = namespaceDecl?.Name ?? "Global";
            }
        }

        private class DependencyVisitor : DepthFirstAstVisitor
        {
            public List<string> Dependencies { get; } = new List<string>();

            public override void VisitSimpleType(SimpleType simpleType)
            {
                Dependencies.Add(simpleType.Identifier);
                base.VisitSimpleType(simpleType);
            }

            public override void VisitMemberReferenceExpression(MemberReferenceExpression memberRef)
            {
                Dependencies.Add(memberRef.MemberName);
                base.VisitMemberReferenceExpression(memberRef);
            }
        }

        private class CallGraphVisitor : DepthFirstAstVisitor
        {
            public HashSet<string> CalledMethods { get; } = new HashSet<string>();

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                if (invocation.Target is MemberReferenceExpression memberRef)
                {
                    CalledMethods.Add(memberRef.MemberName);
                }
                base.VisitInvocationExpression(invocation);
            }
        }

        private float AnalyzeCodeRelationships()
        {
            if (!_contextData.Any()) return 0;

            float relationshipScore = 0;
            foreach (var context in _contextData.Values)
            {
                // Calculate relationship density
                var relationshipDensity = (context.Dependencies.Count + context.RelatedMethods.Count)
                    / (float)_contextData.Count;
                relationshipScore += relationshipDensity;
            }

            return Math.Min(1.0f, relationshipScore / _contextData.Count);
        }

        private float AnalyzeSecurityContextDensity()
        {
            if (!_contextData.Any()) return 0;

            return _contextData.Count(c => c.Value.IsSecurityRelated) / (float)_contextData.Count;
        }

        private float AnalyzeMethodCoupling()
        {
            if (!_contextData.Any()) return 0;

            float totalCoupling = 0;
            foreach (var context in _contextData.Values)
            {
                var couplingScore = (context.Dependencies.Count + context.RelatedMethods.Count)
                    / (float)_contextData.Count;
                totalCoupling += couplingScore;
            }

            return Math.Min(1.0f, totalCoupling / _contextData.Count);
        }

        private float AnalyzeNamespaceOrganization()
        {
            if (!_contextData.Any()) return 0;

            var namespaces = _contextData.Values.Select(c => c.Namespace).Distinct();
            var organizationScore = namespaces.Count() / (float)_contextData.Count;

            return Math.Min(1.0f, organizationScore);
        }

        private float AnalyzeErrorHandlingContext()
        {
            var errorHandlingPatterns = new[] { "try", "catch", "throw", "finally", "exception" };
            return AnalyzeContextPatterns(errorHandlingPatterns);
        }

        private float AnalyzeSecurityPatternContext()
        {
            var securityPatterns = new[] {
                "validate", "sanitize", "authorize", "authenticate", "verify",
                "encrypt", "hash", "protect"
            };
            return AnalyzeContextPatterns(securityPatterns);
        }

        private float AnalyzeVariableUsageContext()
        {
            if (!_contextData.Any()) return 0;

            float usageScore = 0;
            foreach (var context in _contextData.Values)
            {
                var variableReferences = context.CodeBlock.Split(new[] { ' ', '\n', '\r', '\t' })
                    .Where(token => token.Length > 1)
                    .Distinct()
                    .Count();

                usageScore += variableReferences / (float)context.CodeBlock.Length;
            }

            return Math.Min(1.0f, usageScore / _contextData.Count);
        }

        private float AnalyzeMethodComplexityContext()
        {
            if (!_contextData.Any()) return 0;

            var maxComplexity = _contextData.Values.Max(c => c.Complexity);
            var averageComplexity = _contextData.Values.Average(c => c.Complexity);

            return (float)Math.Min(1.0f, averageComplexity / (maxComplexity + 1));
        }

        private float AnalyzeControlFlowContext()
        {
            var controlFlowPatterns = new[] {
                "if", "else", "switch", "case", "for", "foreach", "while", "do"
            };
            return AnalyzeContextPatterns(controlFlowPatterns);
        }

        private float AnalyzeDataFlowContext()
        {
            var dataFlowPatterns = new[] {
                "=", "+=", "-=", "*=", "/=", "|=", "&=", "^=", "<<=", ">>="
            };
            return AnalyzeContextPatterns(dataFlowPatterns);
        }

        private float AnalyzeExceptionContext()
        {
            var exceptionPatterns = new[] {
                "try", "catch", "finally", "throw", "exception"
            };
            return AnalyzeContextPatterns(exceptionPatterns);
        }

        private float AnalyzeResourceContext()
        {
            var resourcePatterns = new[] {
                "using", "dispose", "close", "release", "cleanup"
            };
            return AnalyzeContextPatterns(resourcePatterns);
        }

        private float AnalyzeThreadingContext()
        {
            var threadingPatterns = new[] {
                "thread", "task", "async", "await", "lock", "monitor"
            };
            return AnalyzeContextPatterns(threadingPatterns);
        }

        private float AnalyzeSecurityBoundaryContext()
        {
            var boundaryPatterns = new[] {
                "public", "private", "protected", "internal", "friend"
            };
            return AnalyzeContextPatterns(boundaryPatterns);
        }

        private float AnalyzeInputValidationContext()
        {
            var validationPatterns = new[] {
                "validate", "check", "verify", "assert", "ensure"
            };
            return AnalyzeContextPatterns(validationPatterns);
        }

        private float AnalyzeOutputEncodingContext()
        {
            var encodingPatterns = new[] {
                "encode", "escape", "sanitize", "clean", "format"
            };
            return AnalyzeContextPatterns(encodingPatterns);
        }

        private float AnalyzeAuthenticationContext()
        {
            var authPatterns = new[] {
                "authenticate", "login", "signin", "verify", "identity"
            };
            return AnalyzeContextPatterns(authPatterns);
        }

        private float AnalyzeAuthorizationContext()
        {
            var authzPatterns = new[] {
                "authorize", "permission", "role", "access", "grant"
            };
            return AnalyzeContextPatterns(authzPatterns);
        }

        private float AnalyzeLoggingContext()
        {
            var loggingPatterns = new[] {
                "log", "trace", "debug", "info", "error", "warn"
            };
            return AnalyzeContextPatterns(loggingPatterns);
        }

        private float CalculateOverallContextScore()
        {
            if (!_contextData.Any()) return 0;

            float totalScore = 0;

            foreach (var context in _contextData.Values)
            {
                float contextScore = 0;

                // Method organization score
                contextScore += (context.Dependencies.Count > 0 ? 0.2f : 0);
                contextScore += (context.RelatedMethods.Count > 0 ? 0.2f : 0);

                // Security considerations
                if (context.IsSecurityRelated)
                {
                    contextScore *= 1.2f; // Increase importance of security context
                }

                // Complexity penalty
                float complexityPenalty = Math.Min(0.3f, context.Complexity / 10.0f);
                contextScore = Math.Max(0, contextScore - complexityPenalty);

                // Scope consideration
                switch (context.Scope.ToLower())
                {
                    case "private":
                        contextScore *= 1.1f; // Slight bonus for encapsulation
                        break;
                    case "public":
                        contextScore *= 0.9f; // Slight penalty for exposure
                        break;
                }

                totalScore += contextScore;
            }

            // Normalize to 0-1 range
            return Math.Min(1.0f, totalScore / _contextData.Count);
        }

        private float AnalyzeContextPatterns(string[] patterns)
        {
            if (!_contextData.Any()) return 0;

            float totalScore = 0;
            foreach (var context in _contextData.Values)
            {
                var codeBlock = context.CodeBlock.ToLower();
                float patternScore = patterns.Count(p => codeBlock.Contains(p.ToLower()))
                    / (float)patterns.Length;
                totalScore += patternScore;
            }

            return Math.Min(1.0f, totalScore / _contextData.Count);
        }
    }

    public class ComplexityVisitor : DepthFirstAstVisitor
    {
        public int Complexity { get; private set; } = 0;

        public override void VisitConditionalExpression(ConditionalExpression condition)
        {
            Complexity++;
            base.VisitConditionalExpression(condition);
        }

        public override void VisitBinaryOperatorExpression(BinaryOperatorExpression operation)
        {
            if (operation.Operator == BinaryOperatorType.ConditionalAnd ||
                operation.Operator == BinaryOperatorType.ConditionalOr)
            {
                Complexity++;
            }
            base.VisitBinaryOperatorExpression(operation);
        }

        public override void VisitTryCatchStatement(TryCatchStatement tryCatch)
        {
            Complexity++;
            base.VisitTryCatchStatement(tryCatch);
        }
    }
}