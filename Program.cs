using System;
using System.Threading;
using System.IO;
using System.Reflection;
using RetroDev.UnityGuard.UnityGuard.ML;

namespace UnitySecurityScanner
{
    internal class Program
    {
        static void ShowIntro()
        {
            Console.Clear();
            string logo = @"
██╗   ██╗███╗   ██╗██╗████████╗██╗   ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║   ██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║   ██║██╔██╗ ██║██║   ██║    ╚████╔╝     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║   ██║██║╚██╗██║██║   ██║     ╚██╔╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚██████╔╝██║ ╚████║██║   ██║      ██║       ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝";

            Console.ForegroundColor = ConsoleColor.Cyan;
            foreach (string line in logo.Split('\n'))
            {
                Console.WriteLine(line);
                Thread.Sleep(25);
            }

            string bottomText = @"
======================================================================
              [CREATED BY 0XRETRODEV]  [BUILD: 0.1.14] 
======================================================================";

            foreach (char c in bottomText)
            {
                Console.Write(c);
                Thread.Sleep(5);
            }

            Console.WriteLine("\n");
            Thread.Sleep(250);
            Console.ResetColor();
        }

        static void Main(string[] args)
        {
            try
            {
                ShowIntro();
                Console.WriteLine("Initializing scanner...");

                // Get the directory where the executable is located
                string exePath = Assembly.GetExecutingAssembly().Location;
                string releaseDirectory = Path.GetDirectoryName(exePath);

                // Define default folders relative to the release directory
                string defaultWatchFolder = Path.Combine(releaseDirectory, "ScannerInput");
                string defaultReportsFolder = Path.Combine(releaseDirectory, "Reports");
                string mlModelPath = Path.Combine(releaseDirectory, "security_model.zip");

                // Allow override through command line args but maintain relative paths
                string watchFolder = args.Length > 0
                    ? Path.Combine(releaseDirectory, args[0])
                    : defaultWatchFolder;

                string outputFolder = args.Length > 1
                    ? Path.Combine(releaseDirectory, args[1])
                    : defaultReportsFolder;

                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║       Initializing Security Scanner      ║");
                Console.WriteLine("╚══════════════════════════════════════════╝\n");

                Console.Write("⚡ Creating watch folder... ");
                Directory.CreateDirectory(watchFolder);
                Console.WriteLine("Done ✓");

                Console.Write("⚡ Creating output folder... ");
                Directory.CreateDirectory(outputFolder);
                Console.WriteLine("Done ✓");

                Console.WriteLine("\n╔══════════════════════════════════════════╗");
                Console.WriteLine("║         Loading ML Security Model         ║");
                Console.WriteLine("╚══════════════════════════════════════════╝");

                var mlAnalyzer = new MLSecurityAnalyzer(mlModelPath);

                Console.WriteLine("Starting automated scanner...");
                var scanner = new AutomatedScanner(watchFolder, outputFolder, mlAnalyzer);

                Console.WriteLine("Starting monitoring...");
                scanner.StartMonitoring();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("\nCritical Error During Initialization:");
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine($"Stack Trace: {ex.StackTrace}");
                Console.ResetColor();

                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
        }
    }
}