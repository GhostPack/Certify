using CERTENROLLLib;
using Certify.Lib;
using CommandLine;
using System;
using System.Text;

#if !DISARMED

namespace Certify.Commands
{
    internal class CertRequestDownload
    {
        [Verb("request-download", HelpText = "Download a previously requested certificate")]
        public class Options : DefaultOptions
        {
            [Option("ca", Required = true, HelpText = "Target certificate authority (format: SERVER\\CA-NAME)")]
            public string CertificateAuthority { get; set; }

            [Option("id", Required = true, HelpText = "Target certificate request id")]
            public int RequestId { get; set; }

            [Option("private-key", HelpText = "Target certificate request private key")]
            public string PrivateKey { get; set; }

            [Option("output-pem", HelpText = "Output certificate in PEM format")]
            public bool OutputPem { get; set; }

            [Option("install-machine", SetName = "InstallMachine", HelpText = "Install certificate in the machine store")]
            public bool InstallMachine { get; set; }

            [Option("install-user", SetName = "InstallUser", HelpText = "Install certificate in the user store")]
            public bool InstallUser { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Download a certificate");

            if (!string.IsNullOrEmpty(opts.CertificateAuthority) && !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] The 'certificate authority' parameter is not of the format 'SERVER\\CA-NAME'.");
                return 1;
            }

            var private_key = string.Empty;

            if (!string.IsNullOrEmpty(opts.PrivateKey))
            {
                try
                {
                    private_key = Encoding.UTF8.GetString(Convert.FromBase64String(opts.PrivateKey));
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to decode private key: {e.Message}");
                    return 1;
                }
            }

            Console.WriteLine();
            Console.WriteLine($"[*] Certificate Authority   : {opts.CertificateAuthority}");
            Console.WriteLine($"[*] Request ID              : {opts.RequestId}");
            Console.WriteLine();

            var certificate_pem = string.Empty;

            if (!opts.InstallMachine && !opts.InstallUser)
                certificate_pem = CertEnrollment.DownloadCert(opts.CertificateAuthority, opts.RequestId);
            else if (opts.InstallMachine)
                certificate_pem = CertEnrollment.DownloadAndInstallCert(opts.CertificateAuthority, opts.RequestId, X509CertificateEnrollmentContext.ContextMachine);
            else if (opts.InstallUser)
                certificate_pem = CertEnrollment.DownloadAndInstallCert(opts.CertificateAuthority, opts.RequestId, X509CertificateEnrollmentContext.ContextUser);

            if (!string.IsNullOrEmpty(private_key))
            {
                if (opts.OutputPem)
                {
                    Console.WriteLine("[*] Certificate (PEM)       :");
                    Console.WriteLine();
                    Console.Write(private_key);
                    Console.Write(certificate_pem);
                }
                else
                {
                    Console.WriteLine("[*] Certificate (PFX)       :");
                    Console.WriteLine();
                    Console.WriteLine(Convert.ToBase64String(CertTransformUtil.MakePfx(certificate_pem, private_key)));
                }
            }
            else
            {
                Console.WriteLine("[!] No private key has been provided.");
                Console.WriteLine("[!] - The certificate cannot be used for client authentication.");
                Console.WriteLine();
                Console.WriteLine("[*] Certificate (PEM)       :");
                Console.WriteLine();
                Console.Write(certificate_pem);
            }

            return 0;
        }
    }
}

#endif