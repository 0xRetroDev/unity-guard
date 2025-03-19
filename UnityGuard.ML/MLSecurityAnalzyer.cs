using Microsoft.ML;
using Microsoft.ML.Data;
using RetroDev.UnityGuard.UnityGuard.Onnx;
using System.Text;
using System.Text.Json;
using UnitySecurityScanner;

namespace RetroDev.UnityGuard.UnityGuard.ML
{
    public class MLSecurityAnalyzer
    {
        private readonly MLContext _mlContext;
        private ITransformer _model;
        private readonly string _modelPath;
        private readonly string _trainingDataPath;
        private PredictionEngine<SecurityIssueInput, SecurityIssuePrediction> _predictionEngine;
        private List<SecurityIssueInput> _trainingData;
        private const int RETRAIN_THRESHOLD = 10;
        private int _newExamplesCount = 0;
        private readonly string _modelMetricsPath;
        private readonly string _modelArchivePath;
        private int _modelVersion = 1;
        private List<ModelMetrics> _historicalMetrics = new List<ModelMetrics>();

        // Onnx exporting
        public string OnnxExportPath { get; set; }
        public DateTime? LastOnnxExport { get; set; }


        // Stats tracking
        private DateTime _lastTrainingDate;
        private int _totalExamples;
        private double _currentAccuracy;
        private Dictionary<string, int> _severityDistribution;
        private Dictionary<string, int> _issueTypeDistribution;

        public class ModelMetrics
        {
            public int Version { get; set; }
            public DateTime TrainingDate { get; set; }
            public int TotalExamples { get; set; }
            public double Accuracy { get; set; }
            public Dictionary<string, int> SeverityDistribution { get; set; }
            public Dictionary<string, float> ConfidenceMetrics { get; set; }
            public string OnnxExportPath { get; set; }
            public DateTime? LastOnnxExport { get; set; }
            public string ModelHash { get; set; }
        }

        public MLSecurityAnalyzer(string modelPath = "security_model.zip")
        {
            try
            {
                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║       UNITYGUARD - MODEL INITIALIZATION    ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                _mlContext = new MLContext(seed: 42);

                // Setup AI directory structure
                string aiBaseDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "UnityGuard");

                // Create directory structure
                Console.WriteLine("\nInitializing Unity Guard System:");
                Console.Write("⚡ Creating AI directory structure... ");
                Directory.CreateDirectory(aiBaseDir);
                Console.WriteLine("Done ✓");

                // Initialize all paths relative to AI directory
                _modelPath = Path.Combine(aiBaseDir, "Models", "current_model.zip");
                _trainingDataPath = Path.Combine(aiBaseDir, "Training", "training_data.json");
                _modelArchivePath = Path.Combine(aiBaseDir, "Models", "Archive");
                _modelMetricsPath = Path.Combine(aiBaseDir, "Metrics", "model_metrics.json");

                // Create required subdirectories
                Console.WriteLine("\nSetting up directory structure:");
                CreateAndLogDirectory("Models", Path.Combine(aiBaseDir, "Models"));
                CreateAndLogDirectory("Training Data", Path.Combine(aiBaseDir, "Training"));
                CreateAndLogDirectory("Model Archive", _modelArchivePath);
                CreateAndLogDirectory("Metrics", Path.GetDirectoryName(_modelMetricsPath));

                // Initialize statistics
                Console.WriteLine("\nInitializing system components:");
                Console.Write("⚡ Setting up metrics tracking... ");
                _severityDistribution = new Dictionary<string, int>();
                _issueTypeDistribution = new Dictionary<string, int>();
                Console.WriteLine("Done ✓");

                // Log AI system version and configuration
                Console.WriteLine("\nUnity Guard System Configuration:");
                Console.WriteLine($"├── Version: 0.0.1");
                Console.WriteLine($"├── Base Directory: {aiBaseDir}");
                Console.WriteLine($"├── Model Path: {Path.GetFileName(_modelPath)}");
                Console.WriteLine($"└── Training Data: {Path.GetFileName(_trainingDataPath)}");

                LoadTrainingData();
                LoadModel();

                Console.WriteLine("\n✨ Unity Guard initialization complete!\n");

                Console.WriteLine("\nInitializing system components:");
                Console.Write("⚡ Setting up metrics tracking... ");
                _severityDistribution = new Dictionary<string, int>();
                _issueTypeDistribution = new Dictionary<string, int>();
                _historicalMetrics = new List<ModelMetrics>();

                if (File.Exists(_modelMetricsPath))
                {
                    try
                    {
                        var json = File.ReadAllText(_modelMetricsPath);
                        _historicalMetrics = JsonSerializer.Deserialize<List<ModelMetrics>>(json) ?? new List<ModelMetrics>();

                        // Set the current model version based on historical data
                        if (_historicalMetrics.Any())
                        {
                            _modelVersion = _historicalMetrics.Max(m => m.Version);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"\nWarning: Could not load existing metrics: {ex.Message}");
                        _historicalMetrics = new List<ModelMetrics>();
                    }
                }
                Console.WriteLine("Done ✓");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Error during Unity Guard initialization: {ex.Message}");
                throw;
            }
        }

        public SecurityIssuePrediction AnalyzeIssue(SecurityScanner.SecurityIssue issue)
        {
            var input = new SecurityIssueInput
            {
                IssueType = issue.IssueType,
                Description = issue.Description,
                Context = issue.Context,
                FoundValue = issue.FoundValue,
                CvssScore = (float)issue.CvssScore,
                Location = issue.Location,
                ContainsHardcodedCredentials = DetectHardcodedCredentials(issue),
                ContainsUnsafeCode = DetectUnsafeCode(issue),
                ContainsNetworkCalls = DetectNetworkCalls(issue),
                IsInTestCode = IsTestCode(issue)
            };

            var prediction = _predictionEngine.Predict(input);

            // Enhance prediction with additional analysis
            prediction.IsFalsePositive = CalculateFalsePositiveProbability(issue, prediction);
            prediction.RiskScore = CalculateRiskScore(issue, prediction);
            prediction.RecommendedPriority = DeterminePriority(prediction.RiskScore);

            return prediction;
        }

        public void UpdateModelWithScanResults(List<SecurityScanner.SecurityIssue> issues, bool confirmedResults = false)
        {
            if (!confirmedResults) return;

            var newTrainingData = issues.Select(ConvertToTrainingInput).ToList();
            _trainingData.AddRange(newTrainingData);
            _newExamplesCount += newTrainingData.Count;
            _totalExamples += newTrainingData.Count;

            UpdateDistributions(newTrainingData);
            SaveTrainingData();

            // Retrain if we've hit the threshold
            if (_newExamplesCount >= RETRAIN_THRESHOLD)
            {
                TrainModel();
                _newExamplesCount = 0;
            }
        }

        private void LoadTrainingData()
        {
            Console.Write("\n⚡ Loading training data... ");
            if (File.Exists(_trainingDataPath))
            {
                var json = File.ReadAllText(_trainingDataPath);
                _trainingData = JsonSerializer.Deserialize<List<SecurityIssueInput>>(json);
                _totalExamples = _trainingData.Count;
                UpdateDistributions(_trainingData);
                Console.WriteLine($"Done ✓ (Loaded {_totalExamples} examples)");
            }
            else
            {
                Console.WriteLine("No existing data found");
                Console.Write("⚡ Generating initial training data... ");
                var generator = new SecurityTrainingDataGenerator();
                _trainingData = generator.GenerateComprehensiveTrainingData();
                _totalExamples = _trainingData.Count;
                UpdateDistributions(_trainingData);
                SaveTrainingData();
                Console.WriteLine($"Done ✓ (Generated {_totalExamples} examples)");
            }
        }



        private void SaveTrainingData()
        {
            var json = JsonSerializer.Serialize(_trainingData, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            File.WriteAllText(_trainingDataPath, json);

            // Create backup if needed
            if (_totalExamples % 100 == 0)
            {
                CreateBackup();
            }
        }


        private void LoadModel()
        {
            try
            {
                if (File.Exists(_modelPath))
                {
                    Console.WriteLine($"\nℹ️ Loading model from: {_modelPath}");

                    // Create backup of existing model
                    var backupPath = Path.Combine(
                        _modelArchivePath,
                        $"backup_model_{DateTime.Now:yyyyMMddHHmmss}.zip"
                    );

                    try
                    {
                        File.Copy(_modelPath, backupPath);
                        Console.WriteLine($"✓ Created backup at: {Path.GetFileName(backupPath)}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"ℹ️ Backup skipped: {ex.Message}");
                    }

                    _model = _mlContext.Model.Load(_modelPath, out var modelSchema);
                    _predictionEngine = _mlContext.Model.CreatePredictionEngine<SecurityIssueInput, SecurityIssuePrediction>(_model);

                    Console.WriteLine("✓ Model loaded successfully!");
                }
                else
                {
                    Console.WriteLine("\nℹ️ No existing model found, training new model");
                    TrainModel();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Error loading model: {ex.Message}");
                Console.WriteLine("ℹ️ Training new model instead...");
                TrainModel();
            }
        }

        private void ExportToOnnx(string outputPath = null)
        {
            try
            {
                if (string.IsNullOrEmpty(outputPath))
                {
                    outputPath = Path.Combine(
                        Path.GetDirectoryName(_modelPath),
                        Path.GetFileNameWithoutExtension(_modelPath) + ".onnx"
                    );
                }

                // Ensure the output directory exists
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath));

                var exporter = new OnnxExporter(_mlContext, _trainingDataPath);
                exporter.ConvertModelToOnnx(_modelPath, outputPath);

                // Update metrics
                var currentMetrics = GetCurrentModelMetrics();
                if (currentMetrics != null)
                {
                    currentMetrics.OnnxExportPath = outputPath;
                    currentMetrics.LastOnnxExport = DateTime.UtcNow;
                    SaveMetrics();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Error exporting to ONNX: {ex.Message}");
                throw;
            }
        }


        public void WatchForModelUpdates()
        {
            var modelDir = Path.GetDirectoryName(_modelPath);
            var watcher = new FileSystemWatcher(modelDir)
            {
                Filter = Path.GetFileName(_modelPath),
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.CreationTime
            };

            watcher.Changed += async (s, e) =>
            {
                try
                {
                    // Small delay to ensure file is fully written
                    await Task.Delay(1000);

                    // Reload model on UI thread
                    LoadModel();
                    Console.WriteLine("\n✨ Model hot-reloaded successfully!");

                    // Get and display current metrics after reload
                    var stats = GetTrainingStats();
                    Console.WriteLine($"\n📊 Current Model Statistics:");
                    Console.WriteLine($"Total examples: {stats.totalExamples}");
                    Console.WriteLine($"Model accuracy: {stats.accuracy:P2}");
                    Console.WriteLine($"Last training: {stats.lastTraining:g}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n❌ Error reloading model: {ex.Message}");
                }
            };

            watcher.EnableRaisingEvents = true;
        }

        private void TrainModel()
        {
            Console.WriteLine("\n╔══════════════════════════════════════════╗");
            Console.WriteLine("║         UNITYGUARD - MODEL TRAINING        ║");
            Console.WriteLine("╚══════════════════════════════════════════╝");

            // Display training initialization details
            Console.WriteLine($"\nInitializing Training Session:");
            Console.WriteLine($"├── Model Version: {_modelVersion + 1}");
            Console.WriteLine($"├── Training Examples: {_trainingData.Count}");
            Console.WriteLine($"├── Previous Accuracy: {_currentAccuracy:P2}");
            Console.WriteLine($"└── Last Training: {_lastTrainingDate:g}\n");

            try
            {
                // Data preparation phase
                Console.WriteLine("Phase 1: Data Preparation");
                Console.Write("⚡ Loading training data... ");
                var trainingData = _mlContext.Data.LoadFromEnumerable(_trainingData);
                Console.WriteLine("Done ✓");

                Console.Write("⚡ Building ML pipeline... ");
                var pipeline = BuildTrainingPipeline();
                Console.WriteLine("Done ✓");

                // Training phase
                Console.WriteLine("\nPhase 2: Model Training");
                Console.Write("⚡ Training model with SDCA algorithm... ");
                var trainingStopwatch = System.Diagnostics.Stopwatch.StartNew();
                _model = pipeline.Fit(trainingData);
                trainingStopwatch.Stop();
                Console.WriteLine($"Done ✓ ({trainingStopwatch.ElapsedMilliseconds}ms)");

                // Evaluation phase
                Console.WriteLine("\nPhase 3: Model Evaluation");
                Console.Write("⚡ Generating predictions... ");
                var predictions = _model.Transform(trainingData);
                Console.WriteLine("Done ✓");

                Console.Write("⚡ Computing metrics... ");
                var metrics = _mlContext.MulticlassClassification.Evaluate(
                    predictions,
                    labelColumnName: "Label",
                    predictedLabelColumnName: "PredictedLabel"
                );
                Console.WriteLine("Done ✓");

                // Load current version info
                LoadCurrentVersion();

                _modelVersion++;

                // Model persistence phase
                Console.WriteLine("\nPhase 4: Model Persistence");
                Console.Write("⚡ Saving model artifacts... ");
                var versionedModelPath = Path.Combine(_modelArchivePath, $"model_v{_modelVersion}.zip");
                _mlContext.Model.Save(_model, trainingData.Schema, versionedModelPath);
                File.Copy(versionedModelPath, _modelPath, true);
                Console.WriteLine("Done ✓");

                // Metrics update phase
                Console.Write("⚡ Computing confidence metrics... ");
                var confidenceMetrics = CalculateConfidenceMetrics(predictions);
                var modelHash = CalculateModelHash(versionedModelPath);
                UpdateMetrics(metrics.MicroAccuracy, confidenceMetrics, modelHash);
                Console.WriteLine("Done ✓");

                // ONNX Export phase
                Console.WriteLine("\nPhase 5: ONNX Export");
                Console.Write("⚡ Exporting ONNX model... ");
                var onnxPath = Path.Combine(_modelArchivePath, $"model_v{_modelVersion}.onnx");
                ExportToOnnx(onnxPath);
                Console.WriteLine("Done ✓");

                // Display comprehensive training results
                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║           TRAINING RESULTS                ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                Console.WriteLine("\nModel Performance:");
                Console.WriteLine($"├── Accuracy: {metrics.MicroAccuracy:P2}");
                Console.WriteLine($"├── Macro Accuracy: {metrics.MacroAccuracy:P2}");
                Console.WriteLine($"├── Log Loss: {metrics.LogLoss:F4}");
                Console.WriteLine($"└── Log Loss Reduction: {metrics.LogLossReduction:F4}");

                Console.WriteLine("\nConfidence by Severity:");
                foreach (var conf in confidenceMetrics.OrderByDescending(x => x.Value))
                {
                    var bar = new string('█', (int)(conf.Value * 20));
                    Console.WriteLine($"├── {conf.Key,-8} {bar} ({conf.Value:P1})");
                }

                Console.WriteLine("\nModel Details:");
                Console.WriteLine($"├── Version: {_modelVersion}");
                Console.WriteLine($"├── Hash: {modelHash}");
                Console.WriteLine($"└── Size: {new FileInfo(versionedModelPath).Length / 1024:N0}KB");

                _predictionEngine = _mlContext.Model.CreatePredictionEngine<SecurityIssueInput, SecurityIssuePrediction>(_model);

                // Also update the current model
                File.Copy(versionedModelPath, _modelPath, true);

                // Archive old versions (keep last 5)
                CleanupOldVersions();

                Console.WriteLine("\n✨ Model training successfully completed!\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Error during training: {ex.Message}");
                throw;
            }
        }

        private void CleanupOldVersions(int versionsToKeep = 5)
        {
            try
            {
                // Get all model files
                var modelFiles = Directory.GetFiles(_modelArchivePath, "model_v*.zip")
                    .Concat(Directory.GetFiles(_modelArchivePath, "model_v*.onnx"))
                    .ToList();

                // Extract version numbers and group files
                var versionGroups = modelFiles
                    .Select(f => new
                    {
                        Path = f,
                        Version = int.Parse(Path.GetFileNameWithoutExtension(f).Split('_').Last().Substring(1))
                    })
                    .GroupBy(x => x.Version)
                    .OrderByDescending(g => g.Key)
                    .Skip(versionsToKeep)
                    .ToList();

                // Delete old versions
                foreach (var group in versionGroups)
                {
                    foreach (var file in group)
                    {
                        try
                        {
                            File.Delete(file.Path);
                            Console.WriteLine($"Cleaned up old model version: {Path.GetFileName(file.Path)}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error cleaning up {file.Path}: {ex.Message}");
                        }
                    }

                    // Also cleanup corresponding metrics file
                    var metricsPath = Path.Combine(
                        Path.GetDirectoryName(_modelMetricsPath),
                        $"metrics_v{group.Key}.json"
                    );
                    if (File.Exists(metricsPath))
                    {
                        try
                        {
                            File.Delete(metricsPath);
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during version cleanup: {ex.Message}");
            }
        }

        private void CreateAndLogDirectory(string name, string path)
        {
            Console.Write($"⚡ Creating {name} directory... ");
            Directory.CreateDirectory(path);
            Console.WriteLine("Done ✓");
        }

        private void UpdateMetrics(double accuracy, Dictionary<string, float> confidenceMetrics, string modelHash)
        {
            // Create new metrics record
            var newMetrics = new ModelMetrics
            {
                Version = _modelVersion,
                TrainingDate = DateTime.UtcNow,
                TotalExamples = _trainingData.Count,
                Accuracy = accuracy,
                SeverityDistribution = new Dictionary<string, int>(_severityDistribution),
                ConfidenceMetrics = confidenceMetrics,
                ModelHash = modelHash
            };

            // Remove any existing metrics for this version
            _historicalMetrics.RemoveAll(m => m.Version == _modelVersion);

            // Add to historical metrics
            _historicalMetrics.Add(newMetrics);

            // Update current accuracy
            _currentAccuracy = accuracy;
            _lastTrainingDate = DateTime.UtcNow;

            // Save metrics to file
            SaveMetrics();
        }

        private void SaveMetrics()
        {
            try
            {
                // Ensure metrics directory exists
                Directory.CreateDirectory(Path.GetDirectoryName(_modelMetricsPath));

                var json = JsonSerializer.Serialize(_historicalMetrics, new JsonSerializerOptions
                {
                    WriteIndented = true
                });
                File.WriteAllText(_modelMetricsPath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving metrics: {ex.Message}");
            }
        }

        public void ValidateMetricsFile()
        {
            if (File.Exists(_modelMetricsPath))
            {
                try
                {
                    var json = File.ReadAllText(_modelMetricsPath);
                    var metrics = JsonSerializer.Deserialize<List<ModelMetrics>>(json);

                    if (metrics == null || !metrics.Any())
                    {
                        Console.WriteLine("Warning: Metrics file exists but contains no valid data");
                        return;
                    }

                    Console.WriteLine($"\nMetrics file validation:");
                    Console.WriteLine($"Total records: {metrics.Count}");
                    Console.WriteLine($"Version range: {metrics.Min(m => m.Version)} - {metrics.Max(m => m.Version)}");
                    Console.WriteLine($"Date range: {metrics.Min(m => m.TrainingDate):g} - {metrics.Max(m => m.TrainingDate):g}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\nError validating metrics file: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("\nNo metrics file found");
            }
        }

        private Dictionary<string, float> CalculateConfidenceMetrics(IDataView predictions)
        {


            var scores = new Dictionary<string, List<float>>();

            // Get predictions with scores
            var predictionResults = _mlContext.Data.CreateEnumerable<PredictionResult>(
                predictions, reuseRowObject: false);

            foreach (var pred in predictionResults)
            {
                if (!scores.ContainsKey(pred.PredictedSeverity))
                    scores[pred.PredictedSeverity] = new List<float>();

                // Use maximum score as confidence
                if (pred.Score != null && pred.Score.Length > 0)
                {
                    scores[pred.PredictedSeverity].Add(pred.Score.Max());
                }
            }

            return scores.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.Count > 0 ? kvp.Value.Average() : 0f
            );
        }

        // Create a class to hold prediction results
        public class PredictionResult
        {
            public string PredictedSeverity { get; set; }
            public float[] Score { get; set; }
        }

        private void LoadMetrics()
        {
            if (File.Exists(_modelMetricsPath))
            {
                var json = File.ReadAllText(_modelMetricsPath);
                _historicalMetrics = JsonSerializer.Deserialize<List<ModelMetrics>>(json);
                _modelVersion = _historicalMetrics.Max(m => m.Version);
            }
        }

        private void LoadCurrentVersion()
        {
            try
            {
                // Load metrics to get the latest version
                if (File.Exists(_modelMetricsPath))
                {
                    var json = File.ReadAllText(_modelMetricsPath);
                    _historicalMetrics = JsonSerializer.Deserialize<List<ModelMetrics>>(json) ?? new List<ModelMetrics>();
                    _modelVersion = _historicalMetrics.Any() ? _historicalMetrics.Max(m => m.Version) : 0;
                }
                else
                {
                    _modelVersion = 0;
                    _historicalMetrics = new List<ModelMetrics>();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading version info: {ex.Message}");
                _modelVersion = 0;
                _historicalMetrics = new List<ModelMetrics>();
            }
        }

        private string CalculateModelHash(string modelPath)
        {
            using (var md5 = System.Security.Cryptography.MD5.Create())
            using (var stream = File.OpenRead(modelPath))
            {
                var hash = md5.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }

        // New public methods to access metrics
        public IReadOnlyList<ModelMetrics> GetModelHistory() => _historicalMetrics.AsReadOnly();

        public ModelMetrics GetCurrentModelMetrics() =>
            _historicalMetrics.FirstOrDefault(m => m.Version == _modelVersion);

        public string GetModelEvolutionReport()
        {
            var report = new StringBuilder();
            report.AppendLine("Model Evolution Report");
            report.AppendLine("=====================");

            foreach (var metrics in _historicalMetrics.OrderBy(m => m.Version))
            {
                report.AppendLine($"\nModel Version {metrics.Version}");
                report.AppendLine($"Trained: {metrics.TrainingDate}");
                report.AppendLine($"Examples: {metrics.TotalExamples}");
                report.AppendLine($"Accuracy: {metrics.Accuracy:P2}");
                report.AppendLine("Severity Distribution:");
                foreach (var sev in metrics.SeverityDistribution)
                {
                    report.AppendLine($"  {sev.Key}: {sev.Value}");
                }
                report.AppendLine("Average Confidence by Severity:");
                foreach (var conf in metrics.ConfidenceMetrics)
                {
                    report.AppendLine($"  {conf.Key}: {conf.Value:P2}");
                }
                report.AppendLine($"Model Hash: {metrics.ModelHash}");
            }

            return report.ToString();
        }


        private IEstimator<ITransformer> BuildTrainingPipeline()
        {
            // First map Severity to a key value
            var pipeline = _mlContext.Transforms.Conversion.MapValueToKey(
                    inputColumnName: "Severity",
                    outputColumnName: "Label")

                // Text tokenization and conversion to keys
                .Append(_mlContext.Transforms.Text.TokenizeIntoWords("IssueTypeTokens", "IssueType"))
                .Append(_mlContext.Transforms.Conversion.MapValueToKey("IssueTypeKeys", "IssueTypeTokens"))
                .Append(_mlContext.Transforms.Text.TokenizeIntoWords("DescriptionTokens", "Description"))
                .Append(_mlContext.Transforms.Conversion.MapValueToKey("DescriptionKeys", "DescriptionTokens"))
                .Append(_mlContext.Transforms.Text.TokenizeIntoWords("ContextTokens", "Context"))
                .Append(_mlContext.Transforms.Conversion.MapValueToKey("ContextKeys", "ContextTokens"))

                // Produce ngrams from the key-encoded tokens
                .Append(_mlContext.Transforms.Text.ProduceNgrams("IssueTypeNGrams", "IssueTypeKeys"))
                .Append(_mlContext.Transforms.Text.ProduceNgrams("DescriptionNGrams", "DescriptionKeys"))
                .Append(_mlContext.Transforms.Text.ProduceNgrams("ContextNGrams", "ContextKeys"))

                // Convert boolean features
                .Append(_mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: "HardcodedCredsFeature",
                    inputColumnName: "ContainsHardcodedCredentials",
                    outputKind: DataKind.Single))
                .Append(_mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: "UnsafeCodeFeature",
                    inputColumnName: "ContainsUnsafeCode",
                    outputKind: DataKind.Single))
                .Append(_mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: "NetworkCallsFeature",
                    inputColumnName: "ContainsNetworkCalls",
                    outputKind: DataKind.Single))
                .Append(_mlContext.Transforms.Conversion.ConvertType(
                    outputColumnName: "TestCodeFeature",
                    inputColumnName: "IsInTestCode",
                    outputKind: DataKind.Single))

                // Combine all features
                .Append(_mlContext.Transforms.Concatenate("Features", new[]
                {
            "IssueTypeNGrams",
            "DescriptionNGrams",
            "ContextNGrams",
            "HardcodedCredsFeature",
            "UnsafeCodeFeature",
            "NetworkCallsFeature",
            "TestCodeFeature",
            "CvssScore"
                }))

                // Add the trainer
                .Append(_mlContext.MulticlassClassification.Trainers.SdcaMaximumEntropy(
                    labelColumnName: "Label",
                    featureColumnName: "Features"))

                // Map predictions back
                .Append(_mlContext.Transforms.Conversion.MapKeyToValue(
                    outputColumnName: "PredictedSeverity",
                    inputColumnName: "PredictedLabel"))

                // Add score columns
                .Append(_mlContext.Transforms.CopyColumns(
                    outputColumnName: "Score",
                    inputColumnName: "Score"))
                .Append(_mlContext.Transforms.CopyColumns(
                    outputColumnName: "Probability",
                    inputColumnName: "Score"));

            return pipeline;
        }

        private void CreateBackup()
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var backupDir = Path.Combine(
                Path.GetDirectoryName(_modelPath),
                "Backups",
                timestamp
            );

            Directory.CreateDirectory(backupDir);
            File.Copy(_modelPath, Path.Combine(backupDir, "model.zip"));
            File.Copy(_trainingDataPath, Path.Combine(backupDir, "training_data.json"));
        }

        private void UpdateDistributions(List<SecurityIssueInput> data)
        {
            _severityDistribution = data
                .GroupBy(x => x.Severity)
                .ToDictionary(g => g.Key, g => g.Count());

            _issueTypeDistribution = data
                .GroupBy(x => x.IssueType)
                .ToDictionary(g => g.Key, g => g.Count());
        }

        private SecurityIssueInput ConvertToTrainingInput(SecurityScanner.SecurityIssue issue)
        {
            return new SecurityIssueInput
            {
                IssueType = issue.IssueType,
                Description = issue.Description,
                Context = issue.Context,
                FoundValue = issue.FoundValue,
                CvssScore = (float)issue.CvssScore,
                Location = issue.Location,
                ContainsHardcodedCredentials = DetectHardcodedCredentials(issue),
                ContainsUnsafeCode = DetectUnsafeCode(issue),
                ContainsNetworkCalls = DetectNetworkCalls(issue),
                IsInTestCode = IsTestCode(issue),
                Severity = issue.Severity
            };
        }

        private bool DetectHardcodedCredentials(SecurityScanner.SecurityIssue issue) =>
            issue.IssueType.Contains("Hardcoded") &&
            (issue.IssueType.Contains("API Key") ||
             issue.IssueType.Contains("Password") ||
             issue.IssueType.Contains("Credential"));

        private bool DetectUnsafeCode(SecurityScanner.SecurityIssue issue) =>
            issue.IssueType.Contains("Unsafe") ||
            issue.Context.Contains("unsafe") ||
            issue.Context.Contains("fixed") ||
            issue.Context.Contains("stackalloc");

        private bool DetectNetworkCalls(SecurityScanner.SecurityIssue issue) =>
            issue.Context.Contains("http://") ||
            issue.Context.Contains("https://") ||
            issue.Context.Contains("WWW") ||
            issue.Context.Contains("UnityWebRequest");

        private bool IsTestCode(SecurityScanner.SecurityIssue issue) =>
            issue.Location.Contains("Test") ||
            issue.Location.Contains("Mock") ||
            issue.Context.Contains("[Test]") ||
            issue.Context.Contains("[TestMethod]");

        private bool CalculateFalsePositiveProbability(SecurityScanner.SecurityIssue issue, SecurityIssuePrediction prediction)
        {
            int score = 0;
            if (IsTestCode(issue)) score += 2;
            if (issue.FoundValue.Contains("example") ||
                issue.FoundValue.Contains("test") ||
                issue.FoundValue.Contains("sample")) score += 1;
            if (prediction.Confidence < 0.6f) score += 1;
            if (issue.Location.Contains("Example") ||
                issue.Location.Contains("Demo")) score += 1;
            return score >= 3;
        }

        private float CalculateRiskScore(SecurityScanner.SecurityIssue issue, SecurityIssuePrediction prediction)
        {
            float score = (float)issue.CvssScore;
            score *= prediction.Confidence;
            if (IsTestCode(issue)) score *= 0.5f;
            if (DetectHardcodedCredentials(issue)) score *= 1.2f;
            if (DetectUnsafeCode(issue)) score *= 1.1f;
            return Math.Min(10.0f, score);
        }

        private string DeterminePriority(float riskScore) =>
            riskScore switch
            {
                >= 8.0f => "Immediate Action Required",
                >= 6.0f => "High Priority",
                >= 4.0f => "Medium Priority",
                _ => "Low Priority"
            };

        // Public methods to access statistics
        public (int totalExamples, int newExamples, DateTime lastTraining, double accuracy) GetTrainingStats() =>
            (_totalExamples, _newExamplesCount, _lastTrainingDate, _currentAccuracy);

        public IReadOnlyDictionary<string, int> GetSeverityDistribution() =>
            _severityDistribution;

        public IReadOnlyDictionary<string, int> GetIssueTypeDistribution() =>
            _issueTypeDistribution;
    }
}