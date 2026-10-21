using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace FireflySR.Proxy.Common;

public record ProcessRef(int Id, long Started)
{
    public static ProcessRef Capture(int id)
    {
        using var p = Process.GetProcessById(id);
        return new(id, p.StartTime.ToUniversalTime().Ticks);
    }
    public bool Alive
    {
        get { try { using var p = Process.GetProcessById(Id); return !p.HasExited && p.StartTime.ToUniversalTime().Ticks == Started; } catch { return false; } }
    }
    public void Stop()
    {
        if (!Alive) return;
        using var p = Process.GetProcessById(Id);
        if (p.StartTime.ToUniversalTime().Ticks != Started) return;
        p.Kill();
        p.WaitForExit(15000);
    }
}

public class Lease
{
    public ProcessRef Proxy { get; set; } = null!;
    public ProcessRef Owner { get; set; } = null!;
    public ProcessRef Server { get; set; } = null!;
    public bool StopServer { get; set; }
    public NetSettings Previous { get; set; } = null!;
    public string Endpoint { get; set; } = "";
    public string AppliedBypass { get; set; } = "<local>";
    public string CertificateThumbprint { get; set; } = "";
    public bool PreviouslyTrusted { get; set; }
    public string CertificateStore { get; set; } = "CurrentUser";
    public StoreLocation StoreLocation => CertificateStore == "LocalMachine" ? System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine : System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser;

    public static Lease Create(int port, int owner, int server, bool stopServer, string certificateStore)
    {
        if (certificateStore != "CurrentUser" && certificateStore != "LocalMachine") throw new ArgumentException("Invalid certificate store");
        if (port < 1024 || port > 65535) throw new ArgumentException("Explicit unprivileged proxy port required");
        var previous = NetSettings.Read();
        if ((previous.Flags & 6) != 0)
            throw new InvalidOperationException("An existing manual proxy or PAC is active. Refusing to replace another service's network configuration.");
        // BouncyCastle re-encodes issuer CNs as UTF8String. Windows chain building
        // requires the root Subject DER and leaf Issuer DER to match exactly.
        var rootName = new X500DistinguishedName("CN=Railway Local Development Proxy", X500DistinguishedNameFlags.ForceUTF8Encoding);
        if (File.Exists("root.pfx"))
        {
            using var old = X509CertificateLoader.LoadPkcs12FromFile("root.pfx", null, X509KeyStorageFlags.EphemeralKeySet);
            if (!old.SubjectName.RawData.SequenceEqual(rootName.RawData))
            {
                using var oldStore = new X509Store(StoreName.Root, certificateStore == "LocalMachine" ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
                oldStore.Open(OpenFlags.ReadOnly);
                if (oldStore.Certificates.Find(X509FindType.FindByThumbprint, old.Thumbprint, false).Count > 0) throw new Exception("Recover the previous certificate session before migration");
                File.Move("root.pfx", $"root-legacy-{DateTime.UtcNow.Ticks}.pfx");
            }
        }
        if (!File.Exists("root.pfx"))
        {
            using var key = RSA.Create(3072);
            var req = new CertificateRequest(rootName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            using var created = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(2));
            File.WriteAllBytes("root.pfx", created.Export(X509ContentType.Pfx));
        }
        using var cert = X509CertificateLoader.LoadPkcs12FromFile("root.pfx", null, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        using var store = new X509Store(StoreName.Root, certificateStore == "LocalMachine" ? StoreLocation.LocalMachine : StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return new Lease { Proxy = ProcessRef.Capture(Environment.ProcessId), Owner = ProcessRef.Capture(owner), Server = ProcessRef.Capture(server), StopServer = stopServer,
            Previous = previous, Endpoint = $"http=127.0.0.1:{port};https=127.0.0.1:{port}", AppliedBypass = string.IsNullOrEmpty(previous.Bypass) ? "<local>" : previous.Bypass, CertificateThumbprint = cert.Thumbprint,
            PreviouslyTrusted = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0, CertificateStore = certificateStore };
    }
    public X509Certificate2 LoadCertificate() => X509CertificateLoader.LoadPkcs12FromFile("root.pfx", null, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
    public void Save(string path)
    {
        File.WriteAllText(path + ".tmp", JsonSerializer.Serialize(this));
        for (int i = 0; ; i++)
        {
            try { File.Move(path + ".tmp", path, true); break; }
            catch (IOException) when (i < 100) { Thread.Sleep(50); }
        }
    }
    public void Activate()
    {
        using var cert = LoadCertificate();
        // The elevated client helper installs trust. Read it from a fresh store,
        // never trust an in-memory result from the importing process.
        var until = DateTime.UtcNow.AddSeconds(120);
        for (;;)
        {
            using var check = new X509Store(StoreName.Root, StoreLocation);
            check.Open(OpenFlags.ReadOnly);
            if (check.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false).Count > 0) break;
            if (File.Exists("stop") || DateTime.UtcNow > until) throw new Exception("Windows root trust was not committed; see client-helper-error.log");
            Thread.Sleep(200);
        }
        new NetSettings { Flags = 3, Proxy = Endpoint, Bypass = AppliedBypass }.Apply();
    }
    public static void Recover(string path, ProcessRef? expected = null)
    {
        using var guard = LockRecovery();
        if (File.Exists("stopped")) return;
        var lease = JsonSerializer.Deserialize<Lease>(File.ReadAllText(path)) ?? throw new Exception("Unreadable lease");
        if (expected != null && lease.Proxy != expected) return;
        var current = NetSettings.Read();
        if (current.Proxy == lease.Endpoint && current.Flags == 3 && current.AutoConfig == "" && current.Bypass == lease.AppliedBypass)
            lease.Previous.Apply();
        else if (!current.Equivalent(lease.Previous))
            File.AppendAllText("recovery.log", "Proxy changed externally; preserved new settings." + Environment.NewLine);
        if (!lease.PreviouslyTrusted)
        {
            var until = DateTime.UtcNow.AddSeconds(15);
            while (lease.IsTrusted())
            {
                if (DateTime.UtcNow > until) throw new Exception("Certificate cleanup did not complete; elevated trust watcher may require recovery");
                Thread.Sleep(100);
            }
        }
        File.Delete("ready");
        File.WriteAllText("stopped", DateTimeOffset.UtcNow.ToString("O"));
    }
    public bool IsTrusted()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, CertificateThumbprint, false).Count > 0;
    }
    public void RemoveTrust()
    {
        if (PreviouslyTrusted) return;
        using (var store = new X509Store(StoreName.Root, StoreLocation))
        {
            store.Open(OpenFlags.ReadWrite);
            foreach (var cert in store.Certificates.Find(X509FindType.FindByThumbprint, CertificateThumbprint, false)) store.Remove(cert);
        }
        if (IsTrusted()) throw new Exception("Certificate removal did not persist");
    }
    static FileStream LockRecovery()
    {
        for (int i = 0; ; i++)
        {
            try { return new FileStream("recovery.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (i < 200) { Thread.Sleep(100); }
        }
    }
}
