using System.ComponentModel;
using System.Runtime.InteropServices;

namespace FireflySR.Proxy.Common;

// WinINet per-connection API updates both registry and binary connection settings.
public class NetSettings
{
    public int Flags { get; set; }
    public string Proxy { get; set; } = "";
    public string Bypass { get; set; } = "";
    public string AutoConfig { get; set; } = "";
    public bool Equivalent(NetSettings b) => Flags == b.Flags && Proxy == b.Proxy && Bypass == b.Bypass && AutoConfig == b.AutoConfig;
    [StructLayout(LayoutKind.Explicit, Size = 16)]
    struct Option { [FieldOffset(0)] public int Kind; [FieldOffset(8)] public IntPtr Value; }
    [StructLayout(LayoutKind.Sequential)]
    struct Options { public int Size; public IntPtr Connection; public int Count; public int Error; public IntPtr Items; }
    [DllImport("wininet.dll", EntryPoint = "InternetQueryOptionW", SetLastError = true)]
    static extern bool Query(IntPtr handle, int option, ref Options buffer, ref int size);
    [DllImport("wininet.dll", EntryPoint = "InternetSetOptionW", SetLastError = true)]
    static extern bool Set(IntPtr handle, int option, IntPtr buffer, int size);
    [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr value);

    static NetSettings Transfer(NetSettings? input)
    {
        int stride = Marshal.SizeOf<Option>();
        var items = Marshal.AllocHGlobal(stride * 4);
        var list = new Options { Size = Marshal.SizeOf<Options>(), Count = 4, Items = items };
        var strings = new List<IntPtr>();
        bool queried = false;
        try
        {
            string[] values = [input?.Proxy ?? "", input?.Bypass ?? "", input?.AutoConfig ?? ""];
            for (int i = 0; i < 4; i++)
            {
                IntPtr value = IntPtr.Zero;
                if (input != null)
                {
                    if (i == 0) value = (IntPtr)input.Flags;
                    else { value = Marshal.StringToHGlobalUni(values[i - 1]); strings.Add(value); }
                }
                Marshal.StructureToPtr(new Option { Kind = i + 1, Value = value }, items + i * stride, false);
            }
            if (input == null)
            {
                int size = list.Size;
                if (!Query(IntPtr.Zero, 75, ref list, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                queried = true;
                string Read(int i) => Marshal.PtrToStringUni(Marshal.PtrToStructure<Option>(items + i * stride).Value) ?? "";
                return new NetSettings { Flags = (int)Marshal.PtrToStructure<Option>(items).Value, Proxy = Read(1), Bypass = Read(2), AutoConfig = Read(3) };
            }
            var ptr = Marshal.AllocHGlobal(list.Size);
            try
            {
                Marshal.StructureToPtr(list, ptr, false);
                if (!Set(IntPtr.Zero, 75, ptr, list.Size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!Set(IntPtr.Zero, 39, IntPtr.Zero, 0) || !Set(IntPtr.Zero, 37, IntPtr.Zero, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { Marshal.FreeHGlobal(ptr); }
            return input;
        }
        finally
        {
            if (queried) for (int i = 1; i < 4; i++) GlobalFree(Marshal.PtrToStructure<Option>(items + i * stride).Value);
            foreach (var s in strings) Marshal.FreeHGlobal(s);
            Marshal.FreeHGlobal(items);
        }
    }
    public static NetSettings Read() => Transfer(null);
    public void Apply() => Transfer(this);
}
