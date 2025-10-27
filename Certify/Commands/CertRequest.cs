using CERTENROLLLib;
using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Linq;
using System.DirectoryServices.AccountManagement;

#if !DISARMED

namespace Certify.Commands
{
    internal class CertRequest
    {
        [Verb("request", HelpText = "Request a certificate")]
        public class Options : DefaultOptions
        {
            [Option("ca", Required = true, HelpText = "Target certificate authority (format: SERVER\\CA-NAME)")]
            public string CertificateAuthority { get; set; }

            [Option("template", Required = true, HelpText = "Target certificate template")]
            public string TemplateName { get; set; }

            [Option("subject", HelpText = "Target subject name")]
            public string SubjectName { get; set; }

            [Option("upn", HelpText = "Target subject alternative name (UPN)")]
            public IEnumerable<string> SubjectAltNameUpn { get; set; }

            [Option("dns", HelpText = "Target subject alternative name (DNS)")]
            public IEnumerable<string> SubjectAltNameDns { get; set; }

            [Option("email", HelpText = "Target subject alternative name (Email)")]
            public IEnumerable<string> SubjectAltNameEmail { get; set; }

            [Option("sid-url", HelpText = "Target subject alternative SID (URL format)")]
            public string SubjectAltNameSid { get; set; }

            [Option("sid", HelpText = "Target subject alternative SID")]
            public string SidExtension { get; set; }

            [Option("application-policy", HelpText = "Target application policy")]
            public IEnumerable<string> ApplicationPolicies { get; set; }

            [Option("key-size", Default = 2048, HelpText = "Key size for the private key")]
            public int KeySize { get; set; }

            [Option("machine", HelpText = "Request as the machine account")]
            public bool MachineContext { get; set; }

            [Option("output-pem", HelpText = "Output certificate in PEM format")]
            public bool OutputPem { get; set; }

            [Option("output-csr", HelpText = "Output certificate signing request (CSR)")]
            public bool OutputCSR { get; set; }

            [Option("install", HelpText = "Install certificate in the current store")]
            public bool Install { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Request a certificate");

            if (!string.IsNullOrEmpty(opts.CertificateAuthority) && !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] The 'certificate authority' parameter is not of the format 'SERVER\\CA-NAME'.");
                return 1;
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

            var sans = new List<Tuple<SubjectAltNameType, string>>();

            void AddSubjectAltNames(IEnumerable<string> names, SubjectAltNameType type)
            {
                foreach (var x in names)
                    sans.Add(new Tuple<SubjectAltNameType, string>(type, x));
            }

            AddSubjectAltNames(opts.SubjectAltNameUpn, SubjectAltNameType.Upn);
            AddSubjectAltNames(opts.SubjectAltNameDns, SubjectAltNameType.Dns);
            AddSubjectAltNames(opts.SubjectAltNameEmail, SubjectAltNameType.Email);

            if (!string.IsNullOrEmpty(opts.SubjectAltNameSid))
                sans.Add(new Tuple<SubjectAltNameType, string>(SubjectAltNameType.Url, $"tag:microsoft.com,2022-09-14:sid:{opts.SubjectAltNameSid}"));

            RequestCert(opts, sans);
            return 0;
        }

        private static void RequestCert(Options opts, IEnumerable<Tuple<SubjectAltNameType, string>> sans)
        {
            if (opts.MachineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("[*] Elevating to SYSTEM context for machine cert request");
                ElevationUtil.GetSystem(() => RequestCert(opts, sans));
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine($"[*] Current user context    : {WindowsIdentity.GetCurrent().Name}");

                var subject_name = opts.SubjectName;

                if (string.IsNullOrEmpty(subject_name))
                {
                    if (opts.MachineContext)
                    {
                        subject_name = GetCurrentComputerDN();
                        Console.WriteLine($"[*] No subject name specified, using current machine as subject");
                    }
                    else
                    {
                        if (WindowsIdentity.GetCurrent().IsSystem)
                            Console.WriteLine($"[!] WARNING: You are currently running as SYSTEM. You may want to use the '--machine' argument to use the machine account instead.");

                        subject_name = GetCurrentUserDN();
                        Console.WriteLine($"[*] No subject name specified, using current context as subject.");
                    }
                }
                
                if (string.IsNullOrEmpty(subject_name))
                {
                    subject_name = "CN=User";
                    Console.WriteLine($"[*] Current context did not contain a subject. Using default 'CN=User'.");
                }

                Console.WriteLine();
                Console.WriteLine($"[*] Template                : {opts.TemplateName}");
                Console.WriteLine($"[*] Subject                 : {subject_name}");

                if (sans != null && sans.Any())
                    Console.WriteLine($"[*] Subject Alt Name(s)     : {string.Join(", ", sans.Select(x => x.Item2))}");

                if (!string.IsNullOrEmpty(opts.SidExtension))
                    Console.WriteLine($"[*] Sid Extension           : {opts.SidExtension}");

                if (opts.ApplicationPolicies != null && opts.ApplicationPolicies.Any())
                    Console.WriteLine($"[*] Application Policies    : {string.Join(", ", opts.ApplicationPolicies)}");

                var csr = CertEnrollment.CreateCertRequestMessage(opts.TemplateName, subject_name, sans, 
                    opts.SidExtension, opts.ApplicationPolicies, opts.KeySize, opts.MachineContext);

                Console.WriteLine();
                Console.WriteLine($"[*] Certificate Authority   : {opts.CertificateAuthority}");

                if (opts.OutputCSR)
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Generate Certificate Signing Request (CSR)");
                    Console.WriteLine("[+] Cert Signing Request    :");
                    Console.WriteLine(csr.Item1);
                    Console.WriteLine();
                    Console.WriteLine("[+] Private Key           :");
                    Console.WriteLine(csr.Item2);
                }
                else
                { 
                    try
                    {
                        int request_id = CertEnrollment.SendCertificateRequest(opts.CertificateAuthority, csr.Item1);

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

        private static string GetCurrentUserDN()
        {
            return UserPrincipal.Current.DistinguishedName?.Replace(",", ", ");
        }

        private static string GetCurrentComputerDN()
        {
            return $"CN={System.Net.Dns.GetHostEntry("").HostName}";
        }
    }
}

#endif
