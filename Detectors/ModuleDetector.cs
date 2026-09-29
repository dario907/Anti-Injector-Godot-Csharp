using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using AntiCheat.Telemetry;

namespace AntiCheat.Detectors
{
    public sealed class ModuleDetector : IDetector
    {
        public string Name => "ModuleDetector";

        private static readonly Process Current = Process.GetCurrentProcess();
        private readonly ConcurrentDictionary<string, byte> _known = new (StringComparer.OrdinalIgnoreCase);

        private static readonly string[] SuspiciousDirs =
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
        };

        public void Intiilalize()
        {
            foreach (ProcessModule m in Current.Modules)
                    if (!string .IsNullOrEmpty(m.FIleName))
                        _known.TryAdd(m.FileName, 0);
        }

        public Violation Scan()
        {
            try
            {
                foreach (ProcessModule m in Current.Modules)
                {
                    string path = m.FileName;
                    if (string.IsNullOrEmpty(path)) continue;
                    if (_known.ContainsKey(path)) continue;

                    bool suspicious = isSuspicious(path);

                    if (!suspicious) _known.TryAdd(path, 0);

                    if (suspicious)
                        return new Violation
                        {
                            Detector = Name,
                            Severity = Severity.High,
                            Message = "Suspicious module loaded",
                            Details = path
                        };
                }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return new Violation
                {
                    Detector = Name,
                    Severity = Severity.Medium,
                    Message = "Module enumeration denied (possible tampering)"
                };
            }
            catch (Exception ex)
            {
                return new Violation
                {
                    Detector = Name,
                    Severity = Severity.Low,
                    Message = "Module scan error",
                    Details = ex.ToString()
                };
            }
            return null;
        }

        private static bool isSuspicious(string path)
        {
            foreach (var dir in SuspiciousDirs)
            {
                if (!string.IsNullOrEmpty(dir) && path.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                return true;
            }

            string lower = path.ToLowerInvariant();
            string[] names = { "inject", "cheat", "hack", "trainer", "aimbot", "wallhack" };
            foreach (var n in names) if (lower.Contains(n)) return true;

            return false;
        }
    }
}