using static Injector.Interop;

namespace Injector;

internal static class Log
{
    private static nint _h;

    public static void Init() => _h = GetStdHandle(STD_OUTPUT_HANDLE);

    private static void Write(ushort color, string s)
    {
        SetConsoleTextAttribute(_h, color);
        Console.Write(s);
        SetConsoleTextAttribute(_h, 7);
    }
    public static void Info(string s) => Write(11, s + "\n");
    public static void Ok  (string s) => Write(10, s + "\n");
    public static void Warn(string s) => Write(14, s + "\n");
    public static void Err (string s) => Write(12, s + "\n");
    public static void Banner(string s) => Write(13, s);
}
