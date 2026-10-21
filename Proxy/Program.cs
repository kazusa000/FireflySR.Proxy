using System.Diagnostics;
using System.Text.Json;
using FireflySR.Proxy.Common;

namespace FireflySR.Proxy;

internal class Program
{
    static async Task<int> Main(string[] args)
    {
        Logger.Init("INFO", "Railway local proxy");
        Lease? lease = null;
        ProxyService? service = null;
        FileStream? ownership = null;
        try
        {
            if (args.Length != 5) throw new ArgumentException("Usage: Proxy config state-directory owner-pid server-pid stop-server(0|1)");
            var conf = JsonSerializer.Deserialize<ProxyConfig>(File.ReadAllText(args[0])) ?? throw new Exception("Invalid config");
            Directory.CreateDirectory(args[1]);
            Directory.SetCurrentDirectory(Path.GetFullPath(args[1]));
            ownership = new FileStream("session.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            if (File.Exists("lease.json") && !File.Exists("stopped")) Lease.Recover("lease.json");
            foreach (var f in new[] { "ready", "stopped", "stop", "guardian.ready", "trust-watch.ready", "trust.stopped" }) File.Delete(f);
            lease = Lease.Create(conf.ProxyBindPort, int.Parse(args[2]), int.Parse(args[3]), args[4] == "1", conf.CertificateStore);
            lease.Save("lease.json"); // durable recovery recipe BEFORE any trust/network mutation
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "..", "..", "Guardian", new DirectoryInfo(AppContext.BaseDirectory).Name, "Guardian.dll"));
            start.ArgumentList.Add(Path.GetFullPath("lease.json"));
            using var guardian = Process.Start(start) ?? throw new Exception("Guardian start failed");
            for (int i = 0; !File.Exists("guardian.ready"); i++)
            {
                if (guardian.HasExited || i > 100) throw new Exception("Guardian not ready");
                await Task.Delay(100);
            }
            service = new ProxyService(conf.DestinationHost, conf.DestinationPort, conf, lease.LoadCertificate());
            lease.Activate();
            var helper = JsonSerializer.Deserialize<ProcessRef>(File.ReadAllText("client-helper.json")) ?? throw new Exception("Client helper missing");
            File.WriteAllText("ready", Environment.ProcessId.ToString());
            Logger.Info($"READY loopback=127.0.0.1:{conf.ProxyBindPort}");
            using var cancel = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancel.Cancel(); };
            while (!cancel.IsCancellationRequested && !File.Exists("stop") && lease.Owner.Alive && lease.Server.Alive && helper.Alive && !guardian.HasExited)
                await Task.Delay(250);
            return 0;
        }
        catch (Exception ex) { Logger.Error(ex.ToString()); return 1; }
        finally
        {
            if (lease != null) File.WriteAllText("stop", "proxy ended");
            service?.Shutdown();
            if (lease != null)
            {
                try { Lease.Recover("lease.json", lease.Proxy); }
                catch (Exception ex) { Logger.Error($"Recovery failed; lease retained: {ex}"); }
            }
            ownership?.Dispose();
            Logger.Close();
        }
    }
}
