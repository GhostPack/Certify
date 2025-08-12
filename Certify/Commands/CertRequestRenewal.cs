using CERTENROLLLib;
using Certify.Lib;
using CommandLine;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;

#if !DISARMED

namespace Certify.Commands
{
    internal class CertRequestRenewal
    {
        [Verb("request-renew", HelpText = "Renew a previously requested certificate")]
        public class Options : DefaultOptions
        {
            [Option("ca", Required = true, HelpText = "Target certificate authority (format: SERVER\\CA-NAME)")]
            public string CertificateAuthority { get; set; }

            [Option("cert-pfx", Required = true, HelpText = "Target certificate to renew")]
            public string CertificatePfx { get; set; }

            [Option("cert-pass", HelpText = "Password for certificate")]
            public string CertificatePass { get; set; }

            [Option("machine", HelpText = "Request as the machine account")]
            public bool MachineContext { get; set; }

            [Option("output-pem", HelpText = "Output certificate in PEM format")]
            public bool OutputPem { get; set; }

            [Option("install", HelpText = "Install certificate in the current store")]
            public bool Install { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Request a certificate renewal");

            if (!string.IsNullOrEmpty(opts.CertificateAuthority) && !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] The 'certificate authority' parameter is not of the format 'SERVER\\CA-NAME'.");
                return 1;
            }

            RequestCertRenew(opts);
            return 0;
        }

        private static void RequestCertRenew(Options opts)
        {
            if (opts.MachineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("[*] Elevating to SYSTEM context for machine cert request");
                ElevationUtil.GetSystem(() => RequestCertRenew(opts));
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"[*] Current user context    : {WindowsIdentity.GetCurrent().Name}");

                var cert_bytes = Convert.FromBase64String(opts.CertificatePfx);
                var cert_parts = CertTransformUtil.MakePem(cert_bytes, opts.CertificatePass);

                var cert_x509 = new X509Certificate2(cert_bytes, opts.CertificatePass);
                var cert_req = CertEnrollment.CreateCertRenewMessage(cert_x509, opts.MachineContext);

                Console.WriteLine();
                Console.WriteLine($"[*] Certificate Authority   : {opts.CertificateAuthority}");

                try
                {
                    int request_id = CertEnrollment.SendCertificateRequest(opts.CertificateAuthority, cert_req);

                    Console.WriteLine($"[*] Request ID              : {request_id}");
                    Console.WriteLine();

                    Thread.Sleep(3000);

                    var certificate_pem = string.Empty;

                    if (!opts.Install)
                        certificate_pem = CertEnrollment.DownloadCert(opts.CertificateAuthority, request_id);
                    else
                        certificate_pem = CertEnrollment.DownloadAndInstallCert(opts.CertificateAuthority, request_id, X509CertificateEnrollmentContext.ContextUser);

                    if (opts.OutputPem)
                    {
                        Console.WriteLine("[*] Certificate (PEM)       :");
                        Console.WriteLine();
                        Console.Write(cert_parts.Item2);
                        Console.Write(certificate_pem);
                    }
                    else
                    {
                        Console.WriteLine("[*] Certificate (PFX)       :");
                        Console.WriteLine();
                        Console.WriteLine(Convert.ToBase64String(CertTransformUtil.MakePfx(certificate_pem, cert_parts.Item2)));
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Error requesting the certificate: {e.Message}");
                    Console.WriteLine();
                    Console.WriteLine("[*] Private Key (PEM)       :");
                    Console.WriteLine();

                    if (opts.OutputPem)
                        Console.Write(cert_parts.Item2);
                    else
                        Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(cert_parts.Item2)));
                }
            }
        }
    }
}

#endif