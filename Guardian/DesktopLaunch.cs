using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace FireflySR.Proxy.Guardian;

// Starts the game on a separate, never-shown desktop of the interactive window station, so automated client
// tests neither take the user's focus nor need desktop clicks. Process.Start cannot pick a desktop.
internal sealed class DesktopLaunch : IDisposable
{
    const uint DesktopAllAccess = 0x01FF | 0x000F0000;
    const uint CreateUnicodeEnvironment = 0x00000400;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct StartupInfo
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateDesktopW(string name, IntPtr device, IntPtr devMode, uint flags, uint access, IntPtr attributes);

    [DllImport("user32.dll", SetLastError = true)]
    static extern bool CloseDesktop(IntPtr desktop);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string? application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, string environment, string currentDirectory,
        ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    readonly IntPtr desktop;

    public DesktopLaunch(string name)
    {
        if (name.Length == 0 || name.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')) throw new ArgumentException("Bad desktop name");
        Name = name;
        // Opens the desktop when it already exists; it lives until every handle and process on it is gone.
        desktop = CreateDesktopW(name, IntPtr.Zero, IntPtr.Zero, 0, DesktopAllAccess, IntPtr.Zero);
        if (desktop == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateDesktop failed");
    }

    public string Name { get; }

    public int Start(string exe, IEnumerable<string> arguments, IDictionary<string, string> environmentOverrides)
    {
        var command = new StringBuilder("\"" + exe + "\"");
        foreach (var argument in arguments) command.Append(' ').Append(argument.Contains(' ') ? "\"" + argument + "\"" : argument);
        var environment = Environment.GetEnvironmentVariables().Cast<System.Collections.DictionaryEntry>()
            .ToDictionary(x => (string)x.Key, x => (string?)x.Value ?? "", StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in environmentOverrides) environment[key] = value;
        var block = string.Concat(environment.OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Select(x => x.Key + "=" + x.Value + "\0")) + "\0";
        var startup = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>(), lpDesktop = "WinSta0\\" + Name };
        if (!CreateProcessW(exe, command, IntPtr.Zero, IntPtr.Zero, false, CreateUnicodeEnvironment, block,
                Path.GetDirectoryName(exe)!, ref startup, out var info))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess on desktop failed");
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return info.dwProcessId;
    }

    public void Dispose() => CloseDesktop(desktop);
}
