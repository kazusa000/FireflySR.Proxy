using System;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;
using FireflySR.Proxy.Common;

namespace FireflySR.Proxy
{
    internal class ProxyService
    {
        private readonly ProxyConfig _conf;
        private readonly ProxyServer _webProxyServer;
        private readonly string _targetRedirectHost;
        private readonly int _targetRedirectPort;

        public ProxyService(string targetRedirectHost, int targetRedirectPort, ProxyConfig conf, X509Certificate2 certificate)
        {
            _conf = conf ?? throw new ArgumentNullException(nameof(conf));
            _webProxyServer = new ProxyServer(userTrustRootCertificate: false);
            _webProxyServer.ForwardToUpstreamGateway = false;
            _webProxyServer.EnableTcpServerConnectionPrefetch = false;
            _webProxyServer.EnableHttp2 = false;
            _webProxyServer.ExceptionFunc = ex => Logger.Error(_conf.VerboseErrors ? ex.ToString() : ex.GetType().Name);
            _webProxyServer.CertificateManager.RootCertificate = certificate;

            _webProxyServer.BeforeRequest += BeforeRequest;
            _webProxyServer.BeforeResponse += (_, args) =>
            {
                if (_conf.VerboseErrors && args.UserData is string route)
                    Logger.Info($"RESPONSE {route} status={args.HttpClient.Response.StatusCode}");
                return Task.CompletedTask;
            };
            _webProxyServer.ServerCertificateValidationCallback += OnCertValidation;

            _targetRedirectHost = targetRedirectHost;
            _targetRedirectPort = targetRedirectPort;

            int port = conf.ProxyBindPort == 0 ? Random.Shared.Next(10000, 60000) : conf.ProxyBindPort;
            SetEndPoint(new ExplicitProxyEndPoint(IPAddress.Loopback, port, true));
        }

        private void SetEndPoint(ExplicitProxyEndPoint explicitEP)
        {
            explicitEP.BeforeTunnelConnectRequest += BeforeTunnelConnectRequest;

            _webProxyServer.AddEndPoint(explicitEP);
            _webProxyServer.Start(changeSystemProxySettings: false);

            // Lease owns system settings; the library must never auto-reset them.
        }

        public void Shutdown()
        {
            _webProxyServer?.Stop();
            _webProxyServer?.Dispose();
        }

        private Task BeforeTunnelConnectRequest(object sender, TunnelConnectSessionEventArgs args)
        {
            string hostname = args.HttpClient.Request.RequestUri.Host;
            args.DecryptSsl = ShouldRedirect(hostname);
            if (args.DecryptSsl && _conf.VerboseErrors) Logger.Info("CONNECT " + hostname);

            return Task.CompletedTask;
        }

        private Task OnCertValidation(object sender, CertificateValidationEventArgs args)
        {
            if (args.SslPolicyErrors == SslPolicyErrors.None)
                args.IsValid = true;

            return Task.CompletedTask;
        }

        private bool ShouldForceRedirect(string path)
        {
            foreach (var keyword in _conf.ForceRedirectOnUrlContains)
            {
                if (path.Contains(keyword)) return true;
            }
            return false;
        }

        private bool ShouldBlock(Uri uri)
        {
            var path = uri.AbsolutePath;
            return _conf.BlockUrls.Contains(path);
        }

        private Task BeforeRequest(object sender, SessionEventArgs args)
        {
            string hostname = args.HttpClient.Request.RequestUri.Host;
            if (ShouldRedirect(hostname))
            {
                string requestUrl = args.HttpClient.Request.RequestUri.ToString();
                Uri local = new Uri($"http://{_targetRedirectHost}:{_targetRedirectPort}/");

                Uri builtUrl = new UriBuilder(requestUrl)
                {
                    Scheme = local.Scheme,
                    Host = local.Host,
                    Port = local.Port
                }.Uri;

                string replacedUrl = builtUrl.ToString();

                if (ShouldBlock(builtUrl))
                {
                    Logger.Blocked(hostname + builtUrl.AbsolutePath);
                    args.Respond(new Titanium.Web.Proxy.Http.Response(Encoding.UTF8.GetBytes("Access denied"))
                    {
                        StatusCode = 404,
                        StatusDescription = "Resource Blocked",
                    }, true);
                    return Task.CompletedTask;
                }

                args.HttpClient.Request.Url = replacedUrl;
                args.UserData = hostname + builtUrl.AbsolutePath;

                // Query strings and bodies may contain login credentials.
                Logger.Redirecting($"{args.HttpClient.Request.Method} {hostname}{builtUrl.AbsolutePath} -> 127.0.0.1:{_targetRedirectPort}");
            }

            return Task.CompletedTask;
        }

        private bool ShouldRedirect(string hostname)
        {
            if (hostname.Contains(':'))
                hostname = hostname[..hostname.IndexOf(':')];

            foreach (string domain in _conf.AlwaysIgnoreDomains)
            {
                if (MatchesDomain(hostname, domain))
                {
                    return false;
                }
            }

            foreach (string domain in _conf.RedirectDomains)
            {
                if (MatchesDomain(hostname, domain))
                    return true;
            }

            return false;
        }

        internal static bool MatchesDomain(string host, string domain)
        {
            string suffix = domain.TrimStart('.');
            return host.Equals(suffix, StringComparison.OrdinalIgnoreCase) || host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);
        }
    }
}
