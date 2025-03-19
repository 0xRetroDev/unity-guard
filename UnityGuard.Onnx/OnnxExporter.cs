using Microsoft.ML;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace RetroDev.UnityGuard.UnityGuard.Onnx
{
    public class OnnxExporter
    {
        private readonly MLContext _mlContext;
        private readonly string _trainingDataPath;

        public OnnxExporter(MLContext mlContext, string trainingDataPath)
        {
            _mlContext = mlContext;
            _trainingDataPath = trainingDataPath;
        }

        public void ConvertModelToOnnx(string mlModelPath, string outputPath)
        {
            try
            {
                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║         UNITY GUARD - ONNX EXPORT          ║");
                Console.WriteLine("╚══════════════════════════════════════════╝\n");

                Console.Write("⚡ Loading ML.NET model... ");
                var model = _mlContext.Model.Load(mlModelPath, out var schema);
                Console.WriteLine("Done ✓");

                // Create backup if needed
                if (File.Exists(outputPath))
                {
                    var backupPath = Path.Combine(
                        Path.GetDirectoryName(outputPath),
                        $"backup_{Path.GetFileName(outputPath)}_{DateTime.Now:yyyyMMddHHmmss}"
                    );
                    File.Copy(outputPath, backupPath);
                    Console.WriteLine($"Created backup at: {Path.GetFileName(backupPath)}");
                }

                // Load actual training data
                Console.Write("⚡ Loading training data... ");
                var json = File.ReadAllText(_trainingDataPath);
                var trainingData = JsonSerializer.Deserialize<List<SecurityIssueInput>>(json);
                var data = _mlContext.Data.LoadFromEnumerable(trainingData);
                Console.WriteLine($"Done ✓ (Loaded {trainingData.Count} examples)");

                Console.Write("⚡ Converting to ONNX format... ");
                using (var stream = File.Create(outputPath))
                {
                    _mlContext.Model.ConvertToOnnx(model, data, stream);
                }
                Console.WriteLine("Done ✓");

                // Verify the exported file
                var fileInfo = new FileInfo(outputPath);
                Console.WriteLine($"\nONNX Export Complete:");
                Console.WriteLine($"├── File: {Path.GetFileName(outputPath)}");
                Console.WriteLine($"├── Size: {fileInfo.Length / 1024:N0}KB");
                Console.WriteLine($"└── Path: {fileInfo.DirectoryName}");

                Console.WriteLine("\n✨ ONNX export successfully completed!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Error during ONNX export: {ex.Message}");
                throw;
            }
        }
    }
}
