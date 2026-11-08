using System.Runtime.InteropServices;
using System.Text;

namespace RecentFiles;

// Читає журнал змін NTFS (USN Journal), щоб знайти файли, які видалили —
// навіть через Shift+Delete, і навіть якщо кошик потім очистили.
// Коли файл видаляють звичайним Delete, перед переміщенням у кошик журнал
// лишає запис RENAME_OLD_NAME з ОРИГІНАЛЬНИМ іменем файлу — цей запис не
// зникає, навіть якщо кошик пізніше спорожнили. Shift+Delete лишає прямий
// запис FILE_DELETE з тим самим оригінальним іменем.
//
// УВАГА: читання журналу вимагає прав адміністратора (пряме відкриття тома).
// Якщо програма запущена без них, цей клас повертає порожній список.
internal static class UsnJournal
{
    const uint GENERIC_READ = 0x80000000;
    const uint FILE_SHARE_READ = 0x1;
    const uint FILE_SHARE_WRITE = 0x2;
    const uint OPEN_EXISTING = 3;
    const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    const uint FSCTL_QUERY_USN_JOURNAL = 0x000900f4;
    const uint FSCTL_READ_USN_JOURNAL = 0x000900bb;

    const uint USN_REASON_FILE_DELETE = 0x00000200;
    const uint USN_REASON_RENAME_OLD_NAME = 0x00001000;

    [StructLayout(LayoutKind.Sequential)]
    struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct READ_USN_JOURNAL_DATA_V0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    // Нативна структура — 24 байти (4 + 4 + 16-байтний union); важливо зберегти
    // саме цей розмір, інакше виклик OpenFileById прочитає пам'ять за межами буфера.
    [StructLayout(LayoutKind.Sequential)]
    struct FILE_ID_DESCRIPTOR
    {
        public uint Size;
        public uint Type;
        public long FileId;
        public long _unionPadding;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode,
        IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize,
        out uint lpBytesReturned, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr OpenFileById(IntPtr hVolumeHint, ref FILE_ID_DESCRIPTOR lpFileId,
        uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwFlagsAndAttributes);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern uint GetFinalPathNameByHandleW(IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    static bool IsInvalid(IntPtr h) => h == IntPtr.Zero || h.ToInt64() == -1;

    public sealed record DeletedFile(string Name, string? ParentPath, DateTime Time);

    public static List<DeletedFile> ReadDeletes(char driveLetter, DateTime cutoff)
    {
        var result = new List<DeletedFile>();
        IntPtr vol = IntPtr.Zero;

        try
        {
            vol = CreateFileW($@"\\.\{driveLetter}:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (IsInvalid(vol)) return result;

            USN_JOURNAL_DATA_V0 journal;
            int jdSize = Marshal.SizeOf<USN_JOURNAL_DATA_V0>();
            IntPtr jdBuf = Marshal.AllocHGlobal(jdSize);
            try
            {
                if (!DeviceIoControl(vol, FSCTL_QUERY_USN_JOURNAL, IntPtr.Zero, 0, jdBuf, (uint)jdSize, out _, IntPtr.Zero))
                    return result;
                journal = Marshal.PtrToStructure<USN_JOURNAL_DATA_V0>(jdBuf);
            }
            finally { Marshal.FreeHGlobal(jdBuf); }

            var readData = new READ_USN_JOURNAL_DATA_V0
            {
                StartUsn = journal.FirstUsn,
                ReasonMask = 0xFFFFFFFF, // читаємо все, фільтруємо причину самі нижче
                ReturnOnlyOnClose = 0,
                Timeout = 0,
                BytesToWaitFor = 0,
                UsnJournalID = journal.UsnJournalID
            };

            int rdSize = Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>();
            const int bufSize = 64 * 1024;
            IntPtr inBuf = Marshal.AllocHGlobal(rdSize);
            IntPtr outBuf = Marshal.AllocHGlobal(bufSize);
            try
            {
                int guard = 0;
                while (guard++ < 20000) // запобіжник від нескінченного циклу на пошкодженому журналі
                {
                    Marshal.StructureToPtr(readData, inBuf, false);
                    if (!DeviceIoControl(vol, FSCTL_READ_USN_JOURNAL, inBuf, (uint)rdSize, outBuf, bufSize, out uint bytesReturned, IntPtr.Zero))
                        break;
                    if (bytesReturned <= 8) break;

                    long nextUsn = Marshal.ReadInt64(outBuf, 0);
                    int offset = 8;

                    while (offset + 60 <= bytesReturned)
                    {
                        IntPtr rec = IntPtr.Add(outBuf, offset);
                        uint recordLength = unchecked((uint)Marshal.ReadInt32(rec, 0));
                        if (recordLength < 60 || offset + recordLength > bytesReturned) break;

                        ushort majorVersion = unchecked((ushort)Marshal.ReadInt16(rec, 4));
                        if (majorVersion == 2)
                        {
                            long parentRef = Marshal.ReadInt64(rec, 16);
                            long usnTime = Marshal.ReadInt64(rec, 32);
                            uint reason = unchecked((uint)Marshal.ReadInt32(rec, 40));
                            ushort nameLen = unchecked((ushort)Marshal.ReadInt16(rec, 56));
                            ushort nameOff = unchecked((ushort)Marshal.ReadInt16(rec, 58));

                            bool isRemoval = (reason & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME)) != 0;

                            if (isRemoval && nameLen > 0 && nameOff + nameLen <= recordLength)
                            {
                                DateTime time;
                                try { time = DateTime.FromFileTime(usnTime); }
                                catch { time = DateTime.MinValue; }

                                if (time >= cutoff)
                                {
                                    var nameBytes = new byte[nameLen];
                                    Marshal.Copy(IntPtr.Add(rec, nameOff), nameBytes, 0, nameLen);
                                    var name = Encoding.Unicode.GetString(nameBytes);

                                    // Внутрішні імена кошика ($I.../$R...) не несуть корисної інформації.
                                    if (!name.StartsWith("$I", StringComparison.OrdinalIgnoreCase) &&
                                        !name.StartsWith("$R", StringComparison.OrdinalIgnoreCase))
                                    {
                                        string? parentPath = TryResolveParent(vol, driveLetter, parentRef);
                                        result.Add(new DeletedFile(name, parentPath, time));
                                    }
                                }
                            }
                        }

                        offset += (int)recordLength;
                    }

                    if (nextUsn <= readData.StartUsn) break;
                    readData.StartUsn = nextUsn;
                    if (nextUsn >= journal.NextUsn) break;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(inBuf);
                Marshal.FreeHGlobal(outBuf);
            }
        }
        catch { }
        finally
        {
            if (!IsInvalid(vol)) CloseHandle(vol);
        }

        return result;
    }

    // Пробуємо дізнатись шлях до батьківської папки за її File Reference Number.
    // Якщо не вдається (папку теж перейменовано/видалено) — повертаємо null,
    // і викликач просто покаже саму назву файлу без шляху.
    static string? TryResolveParent(IntPtr volHandle, char driveLetter, long parentFrn)
    {
        IntPtr h = IntPtr.Zero;
        try
        {
            var fid = new FILE_ID_DESCRIPTOR
            {
                Size = (uint)Marshal.SizeOf<FILE_ID_DESCRIPTOR>(),
                Type = 0, // FileIdType — 64-бітний ідентифікатор
                FileId = parentFrn
            };

            h = OpenFileById(volHandle, ref fid, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero, FILE_FLAG_BACKUP_SEMANTICS);
            if (IsInvalid(h)) return null;

            var sb = new StringBuilder(1024);
            uint len = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
            if (len == 0 || len >= sb.Capacity) return null;

            var path = sb.ToString();
            if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path.Substring(4);
            return path;
        }
        catch { return null; }
        finally { if (!IsInvalid(h)) CloseHandle(h); }
    }
}
