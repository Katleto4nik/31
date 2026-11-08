using System.Diagnostics;
using System.Text;

namespace RecentFiles;

internal static class Program
{
    static string? QueryLastAccessSetting()
    {
        try
        {
            var psi = new ProcessStartInfo("fsutil", "behavior query disablelastaccess")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(2000);
            return string.IsNullOrWhiteSpace(output) ? null : output.Trim();
        }
        catch { return null; }
    }

    [STAThread]
    static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        int hours = 10;
        string exts = "pdf,exe,dll,png,jar";
        bool all = false, app = true, sys = false, access = true, popular = false, scan = true, modsJars = false, bulk = false, undelete = true;

        // Необов'язкові параметри: --hours 24 --ext pdf,exe --noscan --all --noappdata --system --popular --modsjars --bulk --noundelete --noaccess
        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i].ToLowerInvariant();
            if (a == "--hours" && i + 1 < args.Length && int.TryParse(args[i + 1], out var h) && h > 0) { hours = h; i++; }
            else if (a == "--ext" && i + 1 < args.Length) { exts = args[++i]; }
            else if (a == "--all") all = true;
            else if (a == "--noscan") scan = false;
            else if (a == "--appdata") app = true;
            else if (a == "--noappdata") app = false;
            else if (a == "--system") sys = true;
            else if (a == "--popular") popular = true;
            else if (a == "--modsjars") modsJars = true;
            else if (a == "--bulk") bulk = true;
            else if (a == "--noundelete") undelete = false;
            else if (a == "--noaccess") access = false;
        }

        var set = new HashSet<string>(
            exts.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(x => x.TrimStart('.')),
            StringComparer.OrdinalIgnoreCase);

        var o = new Options
        {
            Hours = hours,
            Exts = set,
            AllDrives = all,
            IncludeAppData = app,
            IncludeSystem = sys,
            IncludePopular = popular,
            IncludeModsJars = modsJars,
            IncludeBulk = bulk,
            UseUndelete = undelete,
            UseScan = scan,
            UseAccessTime = access
        };

        Console.WriteLine($"Файли ({string.Join(", ", set)}) за останні {hours} год.");
        Console.WriteLine(scan
            ? (all ? "Режим: Recent + UserAssist + Кошик + скан усіх дисків" : "Режим: Recent + UserAssist + Кошик + скан папки користувача")
            : "Режим: Recent + UserAssist + Кошик (без скану файлової системи)");

        var atime = QueryLastAccessSetting();
        if (atime != null)
        {
            var note = atime.Contains("Disabled", StringComparison.OrdinalIgnoreCase)
                ? " -> просто ПЕРЕГЛЯД файлу (без зміни) може не лишати сліду"
                : atime.Contains("Enabled", StringComparison.OrdinalIgnoreCase)
                    ? " -> перегляд файлу теж оновлює його час доступу"
                    : "";
            Console.WriteLine($"NTFS час доступу: {atime}{note}");
        }

        if (undelete)
            Console.WriteLine("Пошук назавжди видалених (Shift+Delete / спорожнений кошик) потребує прав адміністратора — перевірю під час сканування.");

        Console.WriteLine("Сканую, зачекай...");
        Console.WriteLine();

        var list = Collector.Collect(o, CancellationToken.None);

        foreach (var e in list)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(e.Time.ToString("yyyy-MM-dd HH:mm:ss"));
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"  [{e.Kind}/{e.Source}]  ");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine(Path.GetFileName(e.FullPath));
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("    -> " + (Path.GetDirectoryName(e.FullPath) ?? e.FullPath));
            Console.ResetColor();
        }

        Console.WriteLine();
        Console.WriteLine($"Усього: {list.Count}");

        var perExt = string.Join(", ", set.Select(x =>
            $"{x}: {list.Count(e => Path.GetExtension(e.FullPath).TrimStart('.').Equals(x, StringComparison.OrdinalIgnoreCase))}"));
        Console.WriteLine($"По типах -> {perExt}");

        var perSrc = string.Join(", ", Collector.SourceCounts.Select(kv => $"{kv.Key}={kv.Value}"));
        Console.WriteLine($"Джерела  -> {(perSrc.Length == 0 ? "порожньо" : perSrc)}");
        if (Collector.BulkHidden > 0)
            Console.WriteLine($"Приховано як масовий доступ: {Collector.BulkHidden} (запуск з --bulk покаже їх)");
        if (undelete && Collector.IsElevated == false)
            Console.WriteLine("Назавжди видалені файли НЕ перевірені: запусти .exe від імені адміністратора.");
        if (Collector.RecentError != null)
            Console.WriteLine($"Помилка Recent: {Collector.RecentError}");
        Console.WriteLine("Натисни будь-яку клавішу, щоб закрити...");
        try { Console.ReadKey(true); } catch { }
        return 0;
    }
}
