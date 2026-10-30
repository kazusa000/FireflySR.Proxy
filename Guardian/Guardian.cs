using System.Text.Json;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using FireflySR.Proxy.Common;

namespace FireflySR.Proxy.Guardian;

internal class Program
{
    static async Task<int> Main(string[] args)
    {
        // Optional 5th/6th arguments: a background desktop name and the game's command line (automated client tests).
        if (args.Length is >= 3 and <= 6 && args[0] == "--client")
            return await RunClient(args[1], args[2], args.Length >= 4 ? int.Parse(args[3]) : 0,
                args.Length >= 5 ? args[4] : "", args.Length == 6 ? args[5] : "");
        if (args.Length == 3 && args[0] == "--trust-watch") return await WatchTrust(args[1], int.Parse(args[2]));
        if (args.Length == 4 && args[0] == "--session") return await WatchSession(args[1], int.Parse(args[2]), args[3]);
        if (args.Length == 2 && args[0] == "--recover")
        {
            string recoverPath = Path.GetFullPath(args[1]);
            Directory.SetCurrentDirectory(Path.GetDirectoryName(recoverPath)!);
            var old = JsonSerializer.Deserialize<Lease>(File.ReadAllText(recoverPath))!;
            if (old.Proxy.Alive) throw new Exception("Refusing recovery of an active proxy");
            using var cert = old.LoadCertificate();
            if (cert.Thumbprint != old.CertificateThumbprint) throw new Exception("Recovery certificate changed");
            old.RemoveTrust();
            Lease.Recover(recoverPath, old.Proxy);
            if (old.StopServer) old.Server.Stop();
            return 0;
        }
        if (args.Length != 1) return 2;
        string path = Path.GetFullPath(args[0]);
        Directory.SetCurrentDirectory(Path.GetDirectoryName(path)!);
        try
        {
            var lease = JsonSerializer.Deserialize<Lease>(File.ReadAllText(path))!;
            File.WriteAllText("guardian.ready", Environment.ProcessId.ToString());
            while (lease.Proxy.Alive && lease.Owner.Alive && lease.Server.Alive && !File.Exists("stopped"))
                await Task.Delay(250);
            if (!File.Exists("stopped")) lease.Proxy.Stop();
            Lease.Recover(path, lease.Proxy);
            // A live session owner stops the server itself with a clean shutdown that saves the players.
            // Killing it here as soon as the proxy ended lost the progress since the last periodic save.
            if (lease.StopServer && !lease.Owner.Alive) lease.Server.Stop();
            return 0;
        }
        catch (Exception ex)
        {
            File.AppendAllText("recovery-error.log", DateTimeOffset.UtcNow + " " + ex + Environment.NewLine);
            return 1;
        }
    }

    // Elevated only as the game's startup helper; server/proxy stay unelevated.
    // A '-' game path performs certificate/session preparation for integration tests.
    static async Task<int> RunClient(string leasePath, string gamePath, int probeSeconds, string desktopName, string gameArguments)
    {
        using var desktop = desktopName.Length > 0 ? new DesktopLaunch(desktopName) : null;
        string path = Path.GetFullPath(leasePath);
        Directory.SetCurrentDirectory(Path.GetDirectoryName(path)!);
        Lease? lease = null;
        try
        {
            lease = JsonSerializer.Deserialize<Lease>(File.ReadAllText(path))!;
            if (!lease.Proxy.Alive || !lease.Owner.Alive || !lease.Server.Alive) throw new Exception("Session no longer exists");
            File.WriteAllText("client-helper.json", JsonSerializer.Serialize(ProcessRef.Capture(Environment.ProcessId)));
            StopDesktopGame();
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "Guardian.dll"));
            start.ArgumentList.Add("--trust-watch");
            start.ArgumentList.Add(path);
            start.ArgumentList.Add(Environment.ProcessId.ToString());
            using var watcher = Process.Start(start) ?? throw new Exception("Trust watcher start failed");
            for (int i = 0; !File.Exists("trust-watch.ready"); i++)
            {
                if (watcher.HasExited || i > 100) throw new Exception("Trust watcher not ready");
                await Task.Delay(100);
            }
            using (var cert = lease.LoadCertificate())
            {
                if (cert.Thumbprint != lease.CertificateThumbprint) throw new Exception("Certificate identity changed");
                using var store = new X509Store(StoreName.Root, lease.StoreLocation);
                store.Open(OpenFlags.ReadWrite);
                using var publicCert = X509CertificateLoader.LoadCertificate(cert.RawData);
                if (!lease.PreviouslyTrusted) store.Add(publicCert);
            }
            using (var check = new X509Store(StoreName.Root, lease.StoreLocation))
            {
                check.Open(OpenFlags.ReadOnly);
                if (check.Certificates.Find(X509FindType.FindByThumbprint, lease.CertificateThumbprint, false).Count == 0)
                    throw new Exception("Elevated certificate import did not persist");
            }
            File.WriteAllText("trust.ready", lease.CertificateThumbprint);
            var until = DateTime.UtcNow.AddSeconds(30);
            while (!File.Exists("ready"))
            {
                if (!lease.Proxy.Alive || !lease.Owner.Alive || !lease.Server.Alive || DateTime.UtcNow > until)
                    throw new Exception("Proxy not ready");
                await Task.Delay(100);
            }
            ProcessRef? game = null;
            if (gamePath != "-")
            {
                var gameStart = new ProcessStartInfo(Path.GetFullPath(gamePath)) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(gamePath))! };
                // Child-only settings: elevated bootstrap already has the game's required token.
                // Unity's native transport and SDK libcurl may use different proxy discovery paths.
                var endpoint = "http://" + lease.Endpoint.Split(';').Single(x => x.StartsWith("http=", StringComparison.Ordinal))[5..];
                gameStart.Environment["UNITY_PROXYSERVER"] = endpoint;
                gameStart.Environment["HTTP_PROXY"] = endpoint;
                gameStart.Environment["HTTPS_PROXY"] = endpoint;
                gameStart.Environment["ALL_PROXY"] = endpoint;
                gameStart.Environment["NO_PROXY"] = "localhost,127.0.0.1,::1";
                foreach (var argument in gameArguments.Split(' ', StringSplitOptions.RemoveEmptyEntries)) gameStart.ArgumentList.Add(argument);
                if (desktop != null)
                {
                    var overrides = gameStart.Environment.Where(x => x.Value != null && Environment.GetEnvironmentVariable(x.Key) != x.Value)
                        .ToDictionary(x => x.Key, x => x.Value!);
                    game = ProcessRef.Capture(desktop.Start(gameStart.FileName, gameStart.ArgumentList, overrides));
                    File.WriteAllText("desktop-game.json", JsonSerializer.Serialize(game));
                }
                else
                {
                    using var p = Process.Start(gameStart) ?? throw new Exception("Game start failed");
                    game = ProcessRef.Capture(p.Id);
                }
                File.WriteAllText("game.json", JsonSerializer.Serialize(game));
                if (desktop != null)
                {
                    var started = game;
                    new DesktopInput(desktop.Name, () => started.Id).Start(() => started.Alive && !File.Exists("stop"));
                }
            }
            var probeUntil = probeSeconds > 0 ? DateTime.UtcNow.AddSeconds(probeSeconds) : DateTime.MaxValue;
            var nextSnapshot = DateTime.UtcNow.AddSeconds(15);
            var snapshotIndex = 0;
            while (lease.Proxy.Alive && lease.Owner.Alive && lease.Server.Alive && (game == null || game.Alive) && !File.Exists("stop") && !watcher.HasExited)
            {
                if (game != null && probeSeconds > 0 && DateTime.UtcNow >= nextSnapshot)
                {
                    var capture = Task.Run(() => CaptureStartup(game));
                    var result = await Task.WhenAny(capture, Task.Delay(2000)) == capture ? await capture : "Process observation timed out";
                    File.WriteAllText($"game-startup-{snapshotIndex++}.json", result);
                    nextSnapshot = DateTime.UtcNow.AddSeconds(45);
                }
                if (game != null && DateTime.UtcNow >= probeUntil)
                {
                    // Only explicit game-probe mode closes the owned test game.
                    using var p = Process.GetProcessById(game.Id);
                    p.CloseMainWindow();
                    var closeUntil = DateTime.UtcNow.AddSeconds(5);
                    while (game.Alive && DateTime.UtcNow < closeUntil) await Task.Delay(100);
                    if (game.Alive) game.Stop();
                    File.WriteAllText("game-probe-ended", DateTimeOffset.UtcNow.ToString("O"));
                    break;
                }
                await Task.Delay(200);
            }
            return 0;
        }
        catch (Exception ex)
        {
            File.AppendAllText("client-helper-error.log", DateTimeOffset.UtcNow + " " + ex + Environment.NewLine);
            return 1;
        }
        finally
        {
            File.WriteAllText("stop", "client session ended");
            StopDesktopGame();
            if (lease != null && !lease.PreviouslyTrusted)
            {
                try { lease.RemoveTrust(); }
                catch (Exception ex) { File.AppendAllText("client-helper-error.log", "Cleanup: " + ex + Environment.NewLine); }
            }
            File.WriteAllText("client-helper.stopped", DateTimeOffset.UtcNow.ToString("O"));
        }
    }

    // A game on the test desktop cannot be reached or closed by the user, and the unelevated tools may not stop it,
    // so the elevated helper ends it with the session, and at the next session if a previous helper could not.
    static void StopDesktopGame()
    {
        if (!File.Exists("desktop-game.json")) return;
        try
        {
            var game = JsonSerializer.Deserialize<ProcessRef>(File.ReadAllText("desktop-game.json"))!;
            game.Stop();
            if (!game.Alive) File.Delete("desktop-game.json");
        }
        catch (Exception ex) { File.AppendAllText("client-helper-error.log", "Desktop game: " + ex + Environment.NewLine); }
    }

    static string CaptureStartup(ProcessRef game)
    {
        try
        {
            if (!game.Alive) return "Game exited before observation";
            using var p = Process.GetProcessById(game.Id);
            var modules = p.Modules.Cast<ProcessModule>().Select(x => x.ModuleName).ToArray();
            var threads = p.Threads.Cast<ProcessThread>().Take(24).Select(t => new {
                t.Id, State = t.ThreadState.ToString(), Wait = t.ThreadState == System.Diagnostics.ThreadState.Wait ? t.WaitReason.ToString() : ""
            }).ToArray();
            return JsonSerializer.Serialize(new { At = DateTimeOffset.UtcNow, p.Id, CpuMs = p.TotalProcessorTime.TotalMilliseconds,
                p.WorkingSet64, p.MainWindowTitle, Modules = modules, Threads = threads });
        }
        catch (Exception ex) { return JsonSerializer.Serialize(new { Error = ex.ToString() }); }
    }

    static async Task<int> WatchTrust(string leasePath, int helperPid)
    {
        Directory.SetCurrentDirectory(Path.GetDirectoryName(Path.GetFullPath(leasePath))!);
        try
        {
            var lease = JsonSerializer.Deserialize<Lease>(File.ReadAllText(leasePath))!;
            var helper = ProcessRef.Capture(helperPid);
            File.WriteAllText("trust-watch.ready", Environment.ProcessId.ToString());
            while (helper.Alive && lease.Proxy.Alive && lease.Owner.Alive && lease.Server.Alive && !File.Exists("stop")) await Task.Delay(100);
            lease.RemoveTrust();
            File.WriteAllText("trust.stopped", DateTimeOffset.UtcNow.ToString("O"));
            return 0;
        }
        catch (Exception ex)
        {
            File.AppendAllText("trust-recovery-error.log", DateTimeOffset.UtcNow + " " + ex + Environment.NewLine);
            return 1;
        }
    }

    // The server saves its players and exits when shutdown.request appears in its working directory
    // (tools/dev/server.ps1 stop does the same); it is killed only if that does not happen in time.
    static void StopServerCleanly(ProcessRef server, string directory)
    {
        if (!server.Alive) return;
        var request = Path.Combine(directory, "shutdown.request");
        try { File.WriteAllText(request, ""); } catch (IOException) { }
        var until = DateTime.UtcNow.AddSeconds(60);
        while (server.Alive && DateTime.UtcNow < until) Thread.Sleep(250);
        server.Stop();
        try { File.Delete(request); } catch (IOException) { }
    }

    // Starts BEFORE the server. Covers a killed Play process during slow server startup.
    static async Task<int> WatchSession(string directory, int ownerPid, string serverRecord)
    {
        Directory.SetCurrentDirectory(Path.GetFullPath(directory));
        var owner = ProcessRef.Capture(ownerPid);
        File.WriteAllText("session-watch.ready", Environment.ProcessId.ToString());
        while (owner.Alive && !File.Exists("session.done")) await Task.Delay(200);
        try
        {
            if (File.Exists("lease.json"))
            {
                var lease = JsonSerializer.Deserialize<Lease>(File.ReadAllText("lease.json"))!;
                if (lease.Owner == owner)
                {
                    File.WriteAllText("stop", "session owner ended");
                    lease.Proxy.Stop();
                    Lease.Recover("lease.json", lease.Proxy);
                }
            }
        }
        catch (Exception ex) { File.AppendAllText("session-recovery-error.log", ex + Environment.NewLine); }
        finally
        {
            if (File.Exists("owns-server") && File.Exists(serverRecord))
            {
                var server = JsonSerializer.Deserialize<ProcessRef>(File.ReadAllText(serverRecord))!;
                if (server.Started >= owner.Started) StopServerCleanly(server, Path.GetDirectoryName(Path.GetFullPath(serverRecord))!);
            }
            File.WriteAllText("session-watch.stopped", DateTimeOffset.UtcNow.ToString("O"));
        }
        return 0;
    }
}
