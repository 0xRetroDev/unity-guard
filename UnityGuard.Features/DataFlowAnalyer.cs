using System;
using System.Linq;
using System.Collections.Generic;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.CSharp.Syntax;
using ICSharpCode.Decompiler.TypeSystem;

namespace RetroDev.UnityGuard.UnityGuard.Features
{
    public class DataFlowAnalyzer
    {
        private readonly SyntaxTree _syntaxTree;
        private readonly string _code;

        private readonly Dictionary<string, VariableInfo> _variables;
        private readonly Dictionary<string, HashSet<string>> _variableDependencies;
        private readonly HashSet<string> _taintedVariables;

        public DataFlowAnalyzer(SyntaxTree syntaxTree, string code)
        {
            _syntaxTree = syntaxTree;
            _code = code;
            _variables = new Dictionary<string, VariableInfo>();
            _variableDependencies = new Dictionary<string, HashSet<string>>();
            _taintedVariables = new HashSet<string>();
        }

        private class VariableInfo
        {
            public string Name { get; set; }
            public string Type { get; set; }
            public string InitialValue { get; set; }
            public bool IsTainted { get; set; }
            public HashSet<string> DependentVariables { get; set; } = new HashSet<string>();
            public HashSet<string> Sources { get; set; } = new HashSet<string>();
            public HashSet<string> Sinks { get; set; } = new HashSet<string>();
        }

        /// <summary>
        /// Represents the result of data flow analysis
        /// </summary>
        public class DataFlowResult
        {
            public List<DataFlowPath> Paths { get; set; } = new List<DataFlowPath>();
            public Dictionary<string, float> RiskScores { get; set; } = new Dictionary<string, float>();
            public List<DataFlowIssue> Issues { get; set; } = new List<DataFlowIssue>();
        }

        /// <summary>
        /// Represents a path that data takes through the code
        /// </summary>
        public class DataFlowPath
        {
            public string Source { get; set; }
            public List<string> IntermediateNodes { get; set; } = new List<string>();
            public string Sink { get; set; }
            public float RiskScore { get; set; }
            public bool ContainsSanitization { get; set; }
            public string Context { get; set; }
            public int LineNumber { get; set; }
        }

        /// <summary>
        /// Represents a security issue found in data flow
        /// </summary>
        public class DataFlowIssue
        {
            public string Description { get; set; }
            public string Source { get; set; }
            public string Sink { get; set; }
            public float Severity { get; set; }
            public string Recommendation { get; set; }
            public string Context { get; set; }
            public int LineNumber { get; set; }
        }

        /// <summary>
        /// Calculates metrics related to data flow analysis
        /// </summary>
        public float[] CalculateDataFlowMetrics()
        {
            var metrics = new float[10];

            // 1. Taint Propagation Complexity
            metrics[0] = CalculateTaintPropagationComplexity();

            // 2. Data Flow Path Depth
            metrics[1] = CalculateDataFlowPathDepth();

            // 3. Source-Sink Connectivity
            metrics[2] = AnalyzeSourceSinkConnectivity();

            // 4. Average Path Risk Score
            metrics[3] = CalculateAveragePathRiskScore();

            // 5. Sanitization Coverage
            metrics[4] = AnalyzeSanitizationCoverage();

            // 6. Variable Dependency Depth
            metrics[5] = CalculateVariableDependencyDepth();

            // 7. Data Flow Cohesion
            metrics[6] = CalculateDataFlowCohesion();

            // 8. Security Control Coverage
            metrics[7] = AnalyzeSecurityControlCoverage();

            // 9. Cross-Component Data Flow
            metrics[8] = AnalyzeCrossComponentDataFlow();

            // 10. Dynamic Data Flow Complexity
            metrics[9] = AnalyzeDynamicDataFlowComplexity();

            return metrics;
        }

        private float CalculateTaintPropagationComplexity()
        {
            var visitor = new TaintPropagationVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.TaintPropagationCount);
        }

        private float CalculateDataFlowPathDepth()
        {
            var maxDepth = _variables.Values
                .SelectMany(v => v.DependentVariables)
                .GroupBy(v => v)
                .Max(g => g.Count());
            return NormalizeMetric(maxDepth);
        }

        private float AnalyzeSourceSinkConnectivity()
        {
            int totalConnections = _variables.Values.Sum(v =>
                v.Sources.Count * v.Sinks.Count);
            return NormalizeMetric(totalConnections);
        }

        private float CalculateAveragePathRiskScore()
        {
            var result = AnalyzeDataFlow();
            if (result.Paths.Count == 0) return 0;
            return result.Paths.Average(p => p.RiskScore);
        }

        private float AnalyzeSanitizationCoverage()
        {
            int sanitizedVars = _variables.Values.Count(v =>
                HasSanitization(v.Name));
            return sanitizedVars / (float)Math.Max(1, _variables.Count);
        }

        private float CalculateVariableDependencyDepth()
        {
            int maxDepth = 0;
            foreach (var variable in _variables.Values)
            {
                maxDepth = Math.Max(maxDepth,
                    CalculateDependencyChainDepth(variable.Name, new HashSet<string>()));
            }
            return NormalizeMetric(maxDepth);
        }

        private int CalculateDependencyChainDepth(string variable, HashSet<string> visited)
        {
            if (!_variables.ContainsKey(variable) || visited.Contains(variable))
                return 0;

            visited.Add(variable);
            int maxChildDepth = 0;

            foreach (var dep in _variables[variable].DependentVariables)
            {
                maxChildDepth = Math.Max(maxChildDepth,
                    CalculateDependencyChainDepth(dep, visited));
            }

            visited.Remove(variable);
            return 1 + maxChildDepth;
        }

        private float CalculateDataFlowCohesion()
        {
            int totalConnections = 0;
            int possibleConnections = 0;

            foreach (var variable in _variables.Values)
            {
                totalConnections += variable.DependentVariables.Count;
                possibleConnections += _variables.Count - 1;
            }

            return possibleConnections == 0 ? 0 :
                totalConnections / (float)possibleConnections;
        }

        private float AnalyzeSecurityControlCoverage()
        {
            var visitor = new SecurityControlVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.SecurityControlCount);
        }

        private float AnalyzeCrossComponentDataFlow()
        {
            var visitor = new CrossComponentFlowVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.CrossComponentFlowCount);
        }

        private float AnalyzeDynamicDataFlowComplexity()
        {
            var visitor = new DynamicDataFlowVisitor();
            _syntaxTree.AcceptVisitor(visitor);
            return NormalizeMetric(visitor.DynamicFlowComplexity);
        }

        /// <summary>
        /// Performs data flow analysis on the code
        /// </summary>
        public DataFlowResult AnalyzeDataFlow()
        {
            var visitor = new DataFlowVisitor(this);
            _syntaxTree.AcceptVisitor(visitor);

            var result = new DataFlowResult();

            // Build data flow paths
            foreach (var variable in _variables.Values)
            {
                if (variable.Sources.Any())
                {
                    foreach (var source in variable.Sources)
                    {
                        foreach (var sink in variable.Sinks)
                        {
                            var path = BuildDataFlowPath(source, variable.Name, sink);
                            result.Paths.Add(path);

                            // Check for dangerous flows
                            if (IsDangerousFlow(path))
                            {
                                result.Issues.Add(CreateDataFlowIssue(path));
                            }
                        }
                    }
                }
            }

            // Calculate risk scores
            foreach (var variable in _variables.Keys)
            {
                result.RiskScores[variable] = CalculateVariableRisk(_variables[variable]);
            }

            return result;
        }

        private class DataFlowVisitor : DepthFirstAstVisitor
        {
            private readonly DataFlowAnalyzer _analyzer;

            public DataFlowVisitor(DataFlowAnalyzer analyzer)
            {
                _analyzer = analyzer;
            }

            public override void VisitFieldDeclaration(FieldDeclaration fieldDecl)
            {
                foreach (var variable in fieldDecl.Variables)
                {
                    var info = new VariableInfo
                    {
                        Name = variable.Name,
                        Type = fieldDecl.ReturnType.ToString(),
                        InitialValue = variable.Initializer?.ToString()
                    };

                    if (IsUserInput(info.InitialValue))
                    {
                        info.Sources.Add("UserInput");
                        info.IsTainted = true;
                    }

                    _analyzer._variables[variable.Name] = info;
                }

                base.VisitFieldDeclaration(fieldDecl);
            }

            public override void VisitAssignmentExpression(AssignmentExpression assignment)
            {
                if (assignment.Left is IdentifierExpression left)
                {
                    // Track variable dependencies
                    var dependencies = ExtractDependencies(assignment.Right);
                    foreach (var dep in dependencies)
                    {
                        if (_analyzer._variables.ContainsKey(dep))
                        {
                            _analyzer._variables[left.Identifier].DependentVariables.Add(dep);

                            // Propagate taint
                            if (_analyzer._variables[dep].IsTainted)
                            {
                                _analyzer._variables[left.Identifier].IsTainted = true;
                                _analyzer._taintedVariables.Add(left.Identifier);
                            }
                        }
                    }
                }

                base.VisitAssignmentExpression(assignment);
            }

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                // Check for dangerous sinks
                if (IsDangerousSink(invocation))
                {
                    foreach (var arg in invocation.Arguments)
                    {
                        if (arg is IdentifierExpression ident &&
                            _analyzer._variables.ContainsKey(ident.Identifier))
                        {
                            _analyzer._variables[ident.Identifier].Sinks.Add(invocation.ToString());
                        }
                    }
                }

                base.VisitInvocationExpression(invocation);
            }

            private bool IsDangerousSink(InvocationExpression invocation)
            {
                var methodName = invocation.ToString().ToLower();
                return methodName.Contains("execute") ||
                       methodName.Contains("eval") ||
                       methodName.Contains("deserialize") ||
                       methodName.Contains("fromjson") ||
                       methodName.Contains("load");
            }

            private bool IsUserInput(string value)
            {
                if (string.IsNullOrEmpty(value)) return false;

                value = value.ToLower();
                return value.Contains("input.") ||
                       value.Contains("request.") ||
                       value.Contains("getvalue") ||
                       value.Contains("readline") ||
                       value.Contains("parse");
            }

            private HashSet<string> ExtractDependencies(Expression expr)
            {
                var deps = new HashSet<string>();
                var visitor = new DependencyVisitor();
                expr.AcceptVisitor(visitor);
                return visitor.Dependencies;
            }
        }

        private class DependencyVisitor : DepthFirstAstVisitor
        {
            public HashSet<string> Dependencies { get; } = new HashSet<string>();

            public override void VisitIdentifierExpression(IdentifierExpression identifierExpression)
            {
                Dependencies.Add(identifierExpression.Identifier);
                base.VisitIdentifierExpression(identifierExpression);
            }
        }

        private class TaintPropagationVisitor : DepthFirstAstVisitor
        {
            public int TaintPropagationCount { get; private set; } = 0;

            public override void VisitAssignmentExpression(AssignmentExpression assignment)
            {
                // Count taint propagation instances
                if (assignment.Left is IdentifierExpression left &&
                    assignment.Right.ToString().ToLower().Contains("user") ||
                    assignment.Right.ToString().ToLower().Contains("input"))
                {
                    TaintPropagationCount++;
                }
                base.VisitAssignmentExpression(assignment);
            }
        }

        private class SecurityControlVisitor : DepthFirstAstVisitor
        {
            public int SecurityControlCount { get; private set; } = 0;
            private readonly HashSet<string> _securityMethods = new HashSet<string>
            {
                "validate", "sanitize", "escape", "encode", "verify",
                "authenticate", "authorize", "hash", "encrypt"
            };

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                string methodName = invocation.ToString().ToLower();
                if (_securityMethods.Any(m => methodName.Contains(m)))
                {
                    SecurityControlCount++;
                }
                base.VisitInvocationExpression(invocation);
            }
        }

        private class CrossComponentFlowVisitor : DepthFirstAstVisitor
        {
            public int CrossComponentFlowCount { get; private set; } = 0;

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                if (invocation.Target is MemberReferenceExpression mre)
                {
                    // Check for cross-component communication
                    if (mre.Target.ToString().Contains(".") &&
                    !mre.Target.ToString().StartsWith("this"))
                    {
                        CrossComponentFlowCount++;
                    }
                }
                base.VisitInvocationExpression(invocation);
            }
        }

        private class DynamicDataFlowVisitor : DepthFirstAstVisitor
        {
            public int DynamicFlowComplexity { get; private set; } = 0;

            public override void VisitInvocationExpression(InvocationExpression invocation)
            {
                string methodName = invocation.ToString().ToLower();
                if (methodName.Contains("reflection") ||
                    methodName.Contains("dynamic") ||
                    methodName.Contains("invoke") ||
                    methodName.Contains("gettype"))
                {
                    DynamicFlowComplexity++;
                }
                base.VisitInvocationExpression(invocation);
            }
        }

        private DataFlowPath BuildDataFlowPath(string source, string variable, string sink)
        {
            var path = new DataFlowPath
            {
                Source = source,
                Sink = sink,
                ContainsSanitization = HasSanitization(variable),
                Context = GetContext(variable),
                LineNumber = GetLineNumber(variable)
            };

            // Build intermediate nodes
            var current = variable;
            while (_variables.ContainsKey(current) && _variables[current].DependentVariables.Any())
            {
                foreach (var dep in _variables[current].DependentVariables)
                {
                    path.IntermediateNodes.Add(dep);
                    current = dep;
                }
            }

            path.RiskScore = CalculatePathRisk(path);
            return path;
        }

        private bool HasSanitization(string variable)
        {
            if (!_variables.ContainsKey(variable)) return false;

            // Check if any dependencies have sanitization
            foreach (var dep in _variables[variable].DependentVariables)
            {
                var context = GetContext(dep);
                if (context != null && (
                    context.Contains("Sanitize") ||
                    context.Contains("Escape") ||
                    context.Contains("Encode") ||
                    context.Contains("Validate")))
                {
                    return true;
                }
            }

            return false;
        }

        private string GetContext(string variable)
        {
            // Extract code context around the variable usage
            var regex = new System.Text.RegularExpressions.Regex(
                $@"\b{variable}\b.*$",
                System.Text.RegularExpressions.RegexOptions.Multiline
            );

            var match = regex.Match(_code);
            if (match.Success)
            {
                var line = match.Value.Trim();
                return line.Length > 100 ? line.Substring(0, 100) + "..." : line;
            }

            return null;
        }

        private int GetLineNumber(string variable)
        {
            var lines = _code.Split('\n');
            for (int i = 0; i < lines.Length; i++)
            {
                if (lines[i].Contains(variable))
                {
                    return i + 1;
                }
            }
            return 0;
        }

        private bool IsDangerousFlow(DataFlowPath path)
        {
            // Check if path represents a dangerous data flow
            return path.RiskScore > 0.7f && !path.ContainsSanitization;
        }

        private float CalculatePathRisk(DataFlowPath path)
        {
            float risk = 0.0f;

            // Base risk from source
            if (path.Source == "UserInput") risk += 0.4f;

            // Risk from dangerous sinks
            if (IsDangerousSink(path.Sink)) risk += 0.3f;

            // Risk reduction from sanitization
            if (path.ContainsSanitization) risk -= 0.2f;

            // Risk from intermediate nodes
            risk += path.IntermediateNodes.Count * 0.1f;

            return Math.Min(Math.Max(risk, 0.0f), 1.0f);
        }

        private bool IsDangerousSink(string sink)
        {
            sink = sink.ToLower();
            return sink.Contains("execute") ||
                   sink.Contains("eval") ||
                   sink.Contains("deserialize") ||
                   sink.Contains("fromjson") ||
                   sink.Contains("load");
        }

        private float CalculateVariableRisk(VariableInfo variable)
        {
            float risk = 0.0f;

            // Base risk from taint
            if (variable.IsTainted) risk += 0.4f;

            // Risk from dangerous sinks
            risk += variable.Sinks.Count(IsDangerousSink) * 0.2f;

            // Risk from dependencies
            risk += variable.DependentVariables.Count * 0.1f;

            return Math.Min(Math.Max(risk, 0.0f), 1.0f);
        }

        private DataFlowIssue CreateDataFlowIssue(DataFlowPath path)
        {
            return new DataFlowIssue
            {
                Description = $"Potentially dangerous data flow from {path.Source} to {path.Sink}",
                Source = path.Source,
                Sink = path.Sink,
                Severity = path.RiskScore,
                Context = path.Context,
                LineNumber = path.LineNumber,
                Recommendation = GenerateRecommendation(path)
            };
        }

        private string GenerateRecommendation(DataFlowPath path)
        {
            var recommendations = new List<string>();

            if (!path.ContainsSanitization)
            {
                recommendations.Add("Add input sanitization before using the data");
            }

            if (path.Source == "UserInput")
            {
                recommendations.Add("Implement input validation");
            }

            if (IsDangerousSink(path.Sink))
            {
                recommendations.Add("Use parameterized queries or safe APIs");
            }

            return string.Join(". ", recommendations);
        }

        private float NormalizeMetric(float value)
        {
            const float maxValue = 50.0f;
            return Math.Min(value / maxValue, 1.0f);
        }
    }
}