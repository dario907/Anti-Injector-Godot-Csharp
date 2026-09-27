# Anti-Injection Security Guard for Godot (C#)

An asynchronous, multi-layered process protection module written in C# for Godot 4.x. This script detects and mitigates common client-side tampering techniques, including dynamic-link library (**DLL**) injection, remote thread creation, and process debugger attachment.

---

## Overview

In desktop games, cheaters and reverse-engineers often use external software (such as Cheat Engine, DLL injectors, or x64dbg) to manipulate game memory at runtime. 

Because standard Godot assemblies can be inspected, this script acts as an internal guard node that routinely monitors the health of the game's running OS process (`Process.GetCurrentProcess()`) and flags untrusted memory modifications.

### Layers

1. **Module & DLL Injection Scanning:** Captures a baseline of loaded `.dll` files during engine boot. Any DLL loaded into process memory post-launch is inspected against custom security rules.
2. **Native Win32 Anti-Debugging:** Queries kernel-level process flags (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`) via P/Invoke to detect attached debugging or memory-scanning tools.
3. **Remote Thread Detection:** Monitors active thread counts to detect unauthorized threads spawned inside the game's memory space via APIs like `CreateRemoteThread`.
4. **Asynchronous Non-Blocking Execution:** Runs heavy diagnostic routines on background tasks (`Task.Run`) to maintain 60+ FPS without causing frame hitches.

---

## Architectural Setup

```text
[ Game Launch ] ──► Initialize Baseline (Modules & Threads)
                         │
                         ▼
             [ Asynchronous Scan Loop ] (Every N Seconds)
       ┌─────────────────┼─────────────────┐
       ▼                 ▼                 ▼
[ Debugger Check ] [ Module Scan ]  [ Thread Count ]
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
            Violation Detected? (Yes)
                         │
                         ▼
        [ Main Thread Security Response ]
   (Server Telemetry / Graceful Process Termination)