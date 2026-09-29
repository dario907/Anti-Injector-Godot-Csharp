using AntiCheat.Telemetry;

namespace AntiCheat.Detectors
{
    public interface IDetector
    {
        string Name { get; }

        void Intiilalize();

        Violation Scan();
    }
}