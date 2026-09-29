using System;
using System.Diagnostics;
using AntiCheat.Telemetry;

namespace AntiCheat.Detectors
{
    public sealed class ThreadDetector : IDetector
    {
        public string Name => "ThreadDetector";
        public int AllowedVariance { get; set; } = 10;

        private static readonly Process Current = Process.GetCurrentProcess();
        private int  _baseline;

        public void Intiilalize()
        {
            _baseline = Current.Threads.Count;
        }

        public Violation Scan()
        {
            try
            {
                int now = Current.Threads.Count;
                if (now > _baseline + AllowedVariance)
                    return new Violation
                    {
                        Detector = Name,
                        Severity = Severity.Medium,
                        Message = "Thread count Exceeded baseline",
                        Details = $"baseline={_baseline}, now={now}"
                    };
            }
            catch (Exception ex)
            {
                return new Violation
                {
                    Detector = Name,
                    Severity = Severity.Low,
                    Message = "Thread scan error",
                    Details = ex.ToString()
                };
            }
            return null;
        }
    }
}