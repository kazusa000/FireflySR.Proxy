using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace FireflySR.Proxy.Guardian;

// Login bootstrap for automated client tests on a background desktop: captures the game window and posts mouse
// and text messages to it. SendInput only reaches the active desktop, so messages go to the window directly; the
// elevated helper is the only process allowed to post to the elevated game (UIPI).
// Commands arrive as input.json in the session folder; the result is written to input.done.
internal sealed class DesktopInput
{
    record Command(string Op, int X = 0, int Y = 0, string Text = "", string File = "");

    const uint WmMouseMove = 0x0200, WmLButtonDown = 0x0201, WmLButtonUp = 0x0202, WmChar = 0x0102;
    const uint WmKeyDown = 0x0100, WmKeyUp = 0x0101;

    delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr OpenDesktopW(string name, uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(IntPtr desktop);
    [DllImport("user32.dll")] static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] static extern bool EnumDesktopWindows(IntPtr desktop, EnumWindowsProc callback, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int processId);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int size);
    [DllImport("user32.dll")] static extern bool GetClientRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] static extern uint MapVirtualKeyW(uint code, uint mapType);
    [DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr hwnd);
    [DllImport("user32.dll")] static extern int ReleaseDC(IntPtr hwnd, IntPtr hdc);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleDC(IntPtr hdc);
    [DllImport("gdi32.dll")] static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int width, int height);
    [DllImport("gdi32.dll")] static extern IntPtr SelectObject(IntPtr hdc, IntPtr obj);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(IntPtr obj);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(IntPtr hdc);
    [DllImport("gdi32.dll")] static extern int GetDIBits(IntPtr hdc, IntPtr bitmap, uint start, uint lines, byte[] bits, ref BitmapInfo info, uint usage);

    [StructLayout(LayoutKind.Sequential)] struct Rect { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential)]
    struct BitmapInfo
    {
        public int Size, Width, Height;
        public short Planes, BitCount;
        public int Compression, SizeImage, XPelsPerMeter, YPelsPerMeter, ClrUsed, ClrImportant;
    }

    readonly string desktopName;
    readonly Func<int> gameId;

    public DesktopInput(string desktopName, Func<int> gameId)
    {
        this.desktopName = desktopName;
        this.gameId = gameId;
    }

    // Runs on its own thread: SetThreadDesktop only works for a thread that owns no windows or hooks.
    public Thread Start(Func<bool> running)
    {
        var thread = new Thread(() =>
        {
            // Per-monitor aware, so sizes and coordinates are the game's real pixels rather than scaled by display DPI.
            SetThreadDpiAwarenessContext(-4);
            var desktop = OpenDesktopW(desktopName, 0, false, 0x01FF);
            try
            {
                if (desktop == IntPtr.Zero || !SetThreadDesktop(desktop)) throw new Exception("Cannot join the test desktop");
                while (running())
                {
                    if (File.Exists("input.json"))
                    {
                        string result;
                        try
                        {
                            var command = JsonSerializer.Deserialize<Command>(File.ReadAllText("input.json"),
                                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
                            result = Run(desktop, command);
                        }
                        catch (Exception ex) { result = "error: " + ex.Message; }
                        File.Delete("input.json");
                        File.WriteAllText("input.done", result);
                    }
                    Thread.Sleep(100);
                }
            }
            catch (Exception ex) { File.AppendAllText("client-helper-error.log", "Input: " + ex + Environment.NewLine); }
            finally { if (desktop != IntPtr.Zero) CloseDesktop(desktop); }
        }) { IsBackground = true, Name = "desktop-input" };
        thread.Start();
        return thread;
    }

    IntPtr FindWindow(IntPtr desktop)
    {
        IntPtr found = IntPtr.Zero;
        int id = gameId();
        EnumDesktopWindows(desktop, (hwnd, _) =>
        {
            // The game process also owns small helper windows (IME, UAC input indicator); only the Unity window counts.
            GetWindowThreadProcessId(hwnd, out var pid);
            var name = new StringBuilder(64);
            GetClassNameW(hwnd, name, name.Capacity);
            if (pid == id && IsWindowVisible(hwnd) && name.ToString() == "UnityWndClass") { found = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }

    static IntPtr Point(int x, int y) => (IntPtr)((y << 16) | (x & 0xFFFF));

    string Run(IntPtr desktop, Command command)
    {
        var hwnd = FindWindow(desktop);
        if (hwnd == IntPtr.Zero) return "error: no game window on the test desktop";
        GetClientRect(hwnd, out var rect);
        switch (command.Op)
        {
            case "capture":
                return Capture(hwnd, rect.Right - rect.Left, rect.Bottom - rect.Top, command.File);
            case "click":
                PostMessageW(hwnd, WmMouseMove, IntPtr.Zero, Point(command.X, command.Y));
                Thread.Sleep(50);
                PostMessageW(hwnd, WmLButtonDown, 1, Point(command.X, command.Y));
                Thread.Sleep(80);
                PostMessageW(hwnd, WmLButtonUp, IntPtr.Zero, Point(command.X, command.Y));
                return $"clicked {command.X},{command.Y} in {rect.Right}x{rect.Bottom}";
            case "text":
                foreach (var c in command.Text) { PostMessageW(hwnd, WmChar, c, 1); Thread.Sleep(40); }
                return $"typed {command.Text.Length} characters";
            case "key":
                var vk = (uint)command.X;
                var scan = (IntPtr)(1 | (MapVirtualKeyW(vk, 0) << 16));
                PostMessageW(hwnd, WmKeyDown, (IntPtr)vk, scan);
                Thread.Sleep(60);
                PostMessageW(hwnd, WmKeyUp, (IntPtr)vk, scan | unchecked((int)0xC0000000));
                return $"key {vk}";
            default:
                return "error: unknown op " + command.Op;
        }
    }

    // Uncompressed 32-bit BMP of the client area; PW_RENDERFULLCONTENT (2) also captures DirectX content.
    static string Capture(IntPtr hwnd, int width, int height, string file)
    {
        if (width <= 0 || height <= 0) return $"error: empty client area {width}x{height}";
        var screen = GetDC(hwnd);
        var memory = CreateCompatibleDC(screen);
        var bitmap = CreateCompatibleBitmap(screen, width, height);
        var old = SelectObject(memory, bitmap);
        try
        {
            var printed = PrintWindow(hwnd, memory, 2 | 1);
            var info = new BitmapInfo { Size = 40, Width = width, Height = height, Planes = 1, BitCount = 32 };
            var bits = new byte[width * height * 4];
            GetDIBits(memory, bitmap, 0, (uint)height, bits, ref info, 0);
            using var output = File.Create(file);
            using var writer = new BinaryWriter(output);
            writer.Write((byte)'B'); writer.Write((byte)'M');
            writer.Write(54 + bits.Length); writer.Write(0); writer.Write(54);
            writer.Write(40); writer.Write(width); writer.Write(height); writer.Write((short)1); writer.Write((short)32);
            writer.Write(0); writer.Write(bits.Length); writer.Write(0); writer.Write(0); writer.Write(0); writer.Write(0);
            writer.Write(bits);
            return $"captured {width}x{height} printed={printed}";
        }
        finally
        {
            SelectObject(memory, old);
            DeleteObject(bitmap);
            DeleteDC(memory);
            ReleaseDC(hwnd, screen);
        }
    }
}
