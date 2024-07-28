using System;
using System.Diagnostics;

public static class ConsolePlus
{
    public static string ReadLine()
    {
        return Console.ReadLine();
    }
    public static void WriteLine(string message = "", ConsoleColor color = ConsoleColor.White)
    {
        ConsoleColor original = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(message);
        Console.ForegroundColor = original;
    }
    public static void WriteError(string error)
    {
        WriteLine(error, ConsoleColor.Red);
    }
    public static void WriteError(Exception error)
    {
        WriteLine($"Error: {error.Message}.", ConsoleColor.Red);
    }
    public static void WriteWarning(string warning)
    {
        WriteLine(warning, ConsoleColor.DarkYellow);
    }
    public static void WriteWarning(Exception warning)
    {
        WriteLine($"Warning: {warning.Message}.", ConsoleColor.DarkYellow);
    }
    public delegate void Lambda();
    public static void Do(Lambda task)
    {
        try
        {
            task.Invoke();
        }
        catch (Exception ex)
        {
            WriteError(ex);
        }
    }
    public static void NoExcept(Lambda task)
    {
        try
        {
            task?.Invoke();
        }
        catch
        {

        }
    }
    public static void PressAnyKeyToExit()
    {
        WriteLine("Press any key to exit...");
        Stopwatch exitTimer = Stopwatch.StartNew();
        while (true)
        {
            Console.ReadKey(true);
            if (exitTimer.Elapsed.Ticks > 5000000)
            {
                break;
            }
        }
        Environment.Exit(0);
    }
}
