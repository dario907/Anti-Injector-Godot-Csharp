using Godot;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

public partial class AntiInjectionGuard : Node
{
    // Settings configs by you (Godot Inspector)
    [Export] public bool EnableLogging = true;
    [Export] public float ScanIntervalSeconds = 2.0f;
    [Export] public int AllowedThreadVariance = 10;

    // State Tracking
    private HashSet<string> _knownModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private int _baselineThreadCount = 0;
    private double _timer = 0.0;
    private bool _isInitialized = false;

    #region Native Win32 API Imports
    // ..............

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool isDebbugerPresent();

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebbugerPresent);
    #endregion

    public override void _Ready()
    {
        // Set up the platform

        if (OS.GetName() != "Windows")
        {
            SetProcess(false);
            return;
        }

        InitilalizeGuard();
    }

    private void InitilalizeGuard()
    {
        try
        {
            Process currentProcess = Process.GetCurrentProcess();
            
            foreach (ProcessModule module in currentProcess.Modules)
            {
                if (!string.IsNullOrEmpty(module.FileName))
                {
                    _knownModules.Add(module.FileName);
                }
            }

            _baselineThreadCount = currentProcess.Threads.Count;
            _isInitialized = true;

            if (EnableLogging)
            {
                GD.Print("");
            }
        }
        catch (Exception ex)
        {
            GD.PrintErr("");
        }
    }

    public override void _Process(double delta)
    {
        if (!_isInitialized) return;

        _timer += delta;
        if (_timer >= ScanIntervalSeconds)
        {
            _timer = 0.0;

            Task.Run(() =>
            {
                RunDebuggerCheck();
                RunModuleScan();
                RunThreadScan();
            });
        }
    }

    #region Detection Routine 1: Native Debugger Checks

    private void RunDebuggerCheck()
    {
        try
        {
            if (isDebbugerPresent())
            {
                OnSecurityViolation();
                return;
            }

            bool isRemoteAttached = false;
            IntPtr processHandle = Process.GetCurrentProcess().Handle;

            if (CheckRemoteDebuggerPresent(processHandle, ref isRemoteAttached) && isRemoteAttached)
            {
                OnSecurityViolation();
                return;
            }
        }
        catch
        {
            // Handle exceptions or access denied errors from hooks
        }
    }
    #endregion

    #region Detection Routine 2: Module/DLL Injection Scan
    private void RunModuleScan()
    {
        try
        {
            Process currentProcess = Process.GetCurrentProcess();

            foreach (ProcessModule module in currentProcess.Modules)
            {
                string path = module.FileName;

                if (!_knownModules.Contains(path))
                {
                    if (isSuspiciousModule(path))
                    {
                        OnSecurityViolation();
                        return;
                    }

                    // Here you decide if you want to add new modules that are trusted or not
                    _knownModules.Add(path);
                }
            }
        }
        catch (System.ComponentModel.Win32Exception)
        {
            OnSecurityViolation();
        }
        catch (Exception ex)
        {
            // Your excpetion logging
        }
    }

    private bool isSuspiciousModule(string filePath)
    {
        // Your implementation here ->
        // * Compare against forbidden keyword/filename arrays
        // * Check if file is in temp, appdata, or untrusted directories
        // * Validate digital signatures

        string[] blacklist = new string[]
        {
            "",
            "",
            ""
        };

        foreach (string entry in blacklist)
        {
            if (!string.IsNullOrEmpty(entry) && filePath.Contains(entry))
            {
                return true;
            }
        }

        return false;
    }
    #endregion

    #region Detection Routine 3: Remote Thread Creation Scan
    private void RunThreadScan()
    {
        try
        {
            Process currentProcess = Process.GetCurrentProcess();
            int currentThreads = currentProcess.Threads.Count;

            if (currentThreads > _baselineThreadCount + AllowedThreadVariance)
            {
                OnSecurityViolation();
            }
        }
        catch (Exception ex)
        {
            // Your own exception logging
        }
    }
    #endregion

    #region Security Response
    private void OnSecurityViolation()
    {
        // Safe dispatch back to the Godot main thread for UI/network/game handling
        Callable.From(() =>
        {
            // Your implementation
            // 1. Send telemetry packet or ban report to game server
            // 2. Display custom error dialog to player
            // 3. Close or crash process securely

            GD.PrintErr("");

            GetTree().Quit();
        }).CallDeferred();
    }
    #endregion
}
