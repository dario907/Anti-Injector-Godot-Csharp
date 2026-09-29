using System;
using System.Diagnostics;
using AntiCheat.Native;
using AntiCheat.Telemetry;

namespace AntiCheat.Detectors
{
    public sealed class DebuggerDetector : IDetector
    {
        public string Name => "DebuggerDetector";

        public void Intiilalize() { }

        public Violation Scan()
        {
            try
            {
                if (Win32.IsDebbugerPresent())
                    return V("Local debugger attached", Severity.Critical);
                
                bool remote = false;
                IntPtr h = Win32.GetCurrentProcess();
                if (Win32.CheckjRemoteDebuggerPresent(h, ref remote) && remote)
                    return V("Remote debugger attached", Severity.Critical);

                var sw = Stopwatch.StartNew();
                int acc = 0;
                for (int i = 0; i < 10_000; i++) acc += i;
                sw.Stop();
                if (sw.ElapsedMilliseconds > 100 && acc > 0)
                    return V("Timing anomaly - possible debugger", Severity.Medium);
            }
            catch (Exception ex)
            {
                return V("Debugger check threw", Severity.Low, ex.ToString());
            }
            return null;
        }

        private Violation V(string msg, Severity s, string details = "") =>
            new Violation { Detector = Name, Severity = s, Message = msg, Details = details };
    }
}