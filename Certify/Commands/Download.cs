using CERTENROLLLib;
using System;
using System.Collections.Generic;

namespace Certify.Commands
{
    public class Download : ICommand
    {
        public static string CommandName => "download";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Download a Certificates");

            string CA;
            var install = arguments.ContainsKey("/install");

            if (arguments.ContainsKey("/ca"))
            {
                CA = arguments["/ca"];
                if (!CA.Contains("\\"))
                {
                    Console.WriteLine("[X] /ca format of SERVER\\CA-NAME required, you may need to specify \\\\ for escaping purposes");
                    return;
                }
            }
            else
            {
                Console.WriteLine("[X] A /ca:CA is required! (format SERVER\\CA-NAME)");
                return;
            }

            if (!arguments.ContainsKey("/id"))
            {
                Console.WriteLine("[X] A certificate /id:X is required!");
                return;
            }

            if (!int.TryParse(arguments["/id"], out var requestId))
            {
                Console.WriteLine("[X] Invalid certificate ID format: {0}", arguments["/id"]);
                return;
            }

            Console.WriteLine($"[*] Certificates Authority   : {CA}");
            Console.WriteLine($"[*] Request ID              : {requestId}");

            // download the certificate from the CA
            string certPemString;
            if (install)
            {
                var context = arguments.ContainsKey("/computer") || arguments.ContainsKey("/machine")
                    ? X509CertificateEnrollmentContext.ContextMachine
                    : X509CertificateEnrollmentContext.ContextUser;

                certPemString = Cert.DownloadAndInstallCert(CA, requestId, context);
            }
            else
            {
                certPemString = Cert.DownloadCert(CA, requestId);
            }

            // display everything
            Console.WriteLine($"\r\n[*] cert.pem         :\r\n");
            Console.WriteLine(certPemString);
        }
    }
}