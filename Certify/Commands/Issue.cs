using System;
using System.Collections.Generic;


namespace Certify.Commands
{
    class Issue : ICommand
    {
        public static string CommandName => "issue";

        public void Execute(Dictionary<string, string> arguments)
        {

            Console.WriteLine("[*] Action: Issue a pending for approval certificate.");

            var CA = "";


            if (arguments.ContainsKey("/ca"))
            {
                CA = arguments["/ca"];
                if (!CA.Contains("\\"))
                {
                    Console.WriteLine("[X] /ca format of SERVER\\CA-NAME required, you may need to specify \\\\ for escaping purposes");
                    return;
                }
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

            Cert.IssuePendingCertificate(CA, requestId);
        }
    }
}
