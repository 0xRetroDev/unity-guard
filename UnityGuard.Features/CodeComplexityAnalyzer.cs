using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.TypeSystem;

namespace RetroDev.UnityGuard.UnityGuard.Analysis
{
    public class CodeComplexityAnalyzer
    {
        private readonly SyntaxTree _syntaxTree;
        private readonly string _code;

        // Track method-level metrics
        private Dictionary<string, int> _methodComplexity;
        private Dictionary<string, int> _methodNestingDepth;
        private Dictionary<string, HashSet<string>> _methodDependencies;

        public CodeComplexityAnalyzer(SyntaxTree syntaxTree, string code)
        {
            _syntaxTree = syntaxTree;
            _code = code;
            _methodComplexity = new Dictionary<string, int>();
            _methodNestingDepth = new Dictionary<string, int>();
            _methodDependencies = new Dictionary<string, HashSet<string>>();
        }

        public float[] CalculateComplexityMetrics()
        {
            var metrics = new float[10];

            // 1. Cyclomatic Complexity (Control Flow Complexity)
            metrics[0] = CalculateCyclomaticComplexity();

            // 2. Maximum Nesting Depth
            metrics[1] = CalculateMaxNestingDepth();

            // 3. Dependency Count and Coupling
            metrics[2] = AnalyzeDependencies();

            // 4. Average Method Complexity
            metrics[3] = CalculateAverageMethodComplexity();

            // 5. Error Handling Complexity
            metrics[4] = AnalyzeErrorHandlingComplexity();

            // 6. Inheritance Depth
            metrics[5] = CalculateInheritanceDepth();

            // 7. Interface Implementation Complexity
            metrics[6] = AnalyzeInterfaceComplexity();

            // 8. Code Cohesion Score
            metrics[7] = CalculateCodeCohesion();

            // 9. Security-Critical Path Complexity
            metrics[8] = AnalyzeSecurityPathComplexity();

            // 10. Dynamic Code Complexity
            metrics[9] = AnalyzeDynamicCodeComplexity();

            return metrics;
        }

        private float CalculateCyclomaticComplexity()
        {
            var visitor = new CyclomaticComplexityVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.Complexity);
        }

        private float CalculateMaxNestingDepth()
        {
            var visitor = new NestingDepthVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.MaxNestingDepth);
        }

        private float AnalyzeDependencies()
        {
            var visitor = new DependencyVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.Dependencies.Count);
        }

        private float CalculateAverageMethodComplexity()
        {
            var visitor = new MethodComplexityVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.Methods.Count > 0
                ? NormalizeMetric(visitor.TotalComplexity / visitor.Methods.Count)
                : 0;
        }

        private float AnalyzeErrorHandlingComplexity()
        {
            var visitor = new ErrorHandlingVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.ErrorHandlingComplexity);
        }

        private float CalculateInheritanceDepth()
        {
            var visitor = new InheritanceVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.MaxInheritanceDepth);
        }

        private float AnalyzeInterfaceComplexity()
        {
            var visitor = new InterfaceComplexityVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.InterfaceComplexity);
        }

        private float CalculateCodeCohesion()
        {
            var visitor = new CohesionVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return visitor.CalculateCohesionScore();
        }

        private float AnalyzeSecurityPathComplexity()
        {
            var visitor = new SecurityPathVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.SecurityPathComplexity);
        }

        private float AnalyzeDynamicCodeComplexity()
        {
            var visitor = new DynamicCodeVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.DynamicComplexity);
        }

        private float NormalizeMetric(float value)
        {
            // Normalize to a 0-1 range using appropriate scaling
            const float maxValue = 50.0f; // Adjust based on empirical analysis
            return Math.Min(value / maxValue, 1.0f);
        }

        // Visitor classes for different metrics
        private class CyclomaticComplexityVisitor : DepthFirstAstVisitor
        {
            public int Complexity { get; private set; } = 1;

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                Complexity++; // Each method adds complexity
                base.VisitMethodDeclaration(methodDeclaration);
            }

            public override void VisitConditionalExpression(ConditionalExpression conditionalExpression)
            {
                Complexity++; // Ternary operators add complexity
                base.VisitConditionalExpression(conditionalExpression);
            }

            public override void VisitTryCatchStatement(TryCatchStatement tryCatchStatement)
            {
                Complexity++; // Try-catch adds complexity
                base.VisitTryCatchStatement(tryCatchStatement);
            }

            public override void VisitBinaryOperatorExpression(BinaryOperatorExpression binaryOperatorExpression)
            {
                if (binaryOperatorExpression.Operator == BinaryOperatorType.ConditionalAnd ||
                    binaryOperatorExpression.Operator == BinaryOperatorType.ConditionalOr)
                {
                    Complexity++; // Logical operators add complexity
                }
                base.VisitBinaryOperatorExpression(binaryOperatorExpression);
            }
        }

        private class NestingDepthVisitor : DepthFirstAstVisitor
        {
            private int _currentDepth = 0;
            public int MaxNestingDepth { get; private set; } = 0;

            public override void VisitBlockStatement(BlockStatement blockStatement)
            {
                _currentDepth++;
                MaxNestingDepth = Math.Max(MaxNestingDepth, _currentDepth);
                base.VisitBlockStatement(blockStatement);
                _currentDepth--;
            }
        }

        private class DependencyVisitor : DepthFirstAstVisitor
        {
            public HashSet<string> Dependencies { get; } = new HashSet<string>();

            public override void VisitSimpleType(SimpleType simpleType)
            {
                Dependencies.Add(simpleType.Identifier);
                base.VisitSimpleType(simpleType);
            }

            public override void VisitUsingDeclaration(UsingDeclaration usingDeclaration)
            {
                Dependencies.Add(usingDeclaration.ToString());
                base.VisitUsingDeclaration(usingDeclaration);
            }
        }

        private class MethodComplexityVisitor : DepthFirstAstVisitor
        {
            public Dictionary<string, int> Methods { get; } = new Dictionary<string, int>();
            public int TotalComplexity => Methods.Values.Sum();

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                var complexityVisitor = new CyclomaticComplexityVisitor();
                methodDeclaration.AcceptVisitor(complexityVisitor);
                Methods[methodDeclaration.Name] = complexityVisitor.Complexity;
                base.VisitMethodDeclaration(methodDeclaration);
            }
        }

        private class ErrorHandlingVisitor : DepthFirstAstVisitor
        {
            public int ErrorHandlingComplexity { get; private set; } = 0;

            public override void VisitTryCatchStatement(TryCatchStatement tryCatchStatement)
            {
                ErrorHandlingComplexity += tryCatchStatement.CatchClauses.Count;
                base.VisitTryCatchStatement(tryCatchStatement);
            }

            public override void VisitThrowStatement(ThrowStatement throwStatement)
            {
                ErrorHandlingComplexity++;
                base.VisitThrowStatement(throwStatement);
            }
        }

        private class InheritanceVisitor : DepthFirstAstVisitor
        {
            public int MaxInheritanceDepth { get; private set; } = 0;
            private Dictionary<string, int> _classDepths = new Dictionary<string, int>();

            public override void VisitTypeDeclaration(TypeDeclaration typeDeclaration)
            {
                int depth = 1; // Start at 1 for the class itself

                if (typeDeclaration.BaseTypes.Any())
                {
                    foreach (var baseType in typeDeclaration.BaseTypes)
                    {
                        if (_classDepths.TryGetValue(baseType.ToString(), out int baseDepth))
                        {
                            depth += baseDepth;
                        }
                    }
                }

                _classDepths[typeDeclaration.Name] = depth;
                MaxInheritanceDepth = Math.Max(MaxInheritanceDepth, depth);

                base.VisitTypeDeclaration(typeDeclaration);
            }
        }

        private class InterfaceComplexityVisitor : DepthFirstAstVisitor
        {
            public int InterfaceComplexity { get; private set; } = 0;

            public override void VisitTypeDeclaration(TypeDeclaration typeDeclaration)
            {
                if (typeDeclaration.ClassType == ClassType.Interface)
                {
                    InterfaceComplexity += typeDeclaration.Members.Count;
                }
                base.VisitTypeDeclaration(typeDeclaration);
            }
        }

        private class CohesionVisitor : DepthFirstAstVisitor
        {
            private HashSet<string> _sharedFields = new HashSet<string>();
            private HashSet<string> _methodCalls = new HashSet<string>();
            private int _totalMembers = 0;

            public override void VisitFieldDeclaration(FieldDeclaration fieldDeclaration)
            {
                _totalMembers++;
                base.VisitFieldDeclaration(fieldDeclaration);
            }

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                _totalMembers++;
                base.VisitMethodDeclaration(methodDeclaration);
            }

            public override void VisitMemberReferenceExpression(MemberReferenceExpression memberReferenceExpression)
            {
                _sharedFields.Add(memberReferenceExpression.MemberName);
                base.VisitMemberReferenceExpression(memberReferenceExpression);
            }

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    _methodCalls.Add(mre.MemberName);
                }
                base.VisitInvocationExpression(invocationExpression);
            }

            public float CalculateCohesionScore()
            {
                if (_totalMembers == 0) return 0;
                float sharedUsage = (_sharedFields.Count + _methodCalls.Count) / (float)_totalMembers;
                return Math.Min(sharedUsage, 1.0f);
            }
        }

        private class DynamicCodeVisitor : DepthFirstAstVisitor
        {
            public int DynamicComplexity { get; private set; } = 0;

            public override void VisitInvocationExpression(InvocationExpression invocationExpression)
            {
                if (invocationExpression.Target is MemberReferenceExpression mre)
                {
                    // Check for reflection and dynamic code execution
                    string memberName = mre.MemberName.ToLower();
                    if (memberName.Contains("invoke") ||
                        memberName.Contains("reflect") ||
                        memberName.Contains("dynamic") ||
                        memberName.Contains("eval") ||
                        memberName.Contains("compile"))
                    {
                        DynamicComplexity++;
                    }
                }
                base.VisitInvocationExpression(invocationExpression);
            }
        }

        private class SecurityPathVisitor : DepthFirstAstVisitor
        {
            public int SecurityPathComplexity { get; private set; } = 0;
            private readonly HashSet<string> _securityRelatedMethods = new HashSet<string>
            {
                "authenticate", "authorize", "validate", "verify",
                "encrypt", "decrypt", "hash", "sign",
                "sanitize", "escape", "filter"
            };

            public override void VisitMethodDeclaration(MethodDeclaration methodDeclaration)
            {
                string methodName = methodDeclaration.Name.ToLower();
                if (_securityRelatedMethods.Any(s => methodName.Contains(s)))
                {
                    // Calculate complexity for security-related methods
                    var complexityVisitor = new CyclomaticComplexityVisitor();
                    methodDeclaration.AcceptVisitor(complexityVisitor);
                    SecurityPathComplexity += complexityVisitor.Complexity;
                }
                base.VisitMethodDeclaration(methodDeclaration);
            }
        }
    }
}