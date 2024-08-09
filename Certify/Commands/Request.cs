using System;
using System.Collections.Generic;

namespace Certify.Commands
{
    public class Request : ICommand
    {
        public static string CommandName => "request";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Request a Certificates");

            var CA = "";
            var subject = "";
            var altName = "";
            var sidExtension = "";
            var template = "User";
            var machineContext = false;
            var install = false;
            var keySize = 2048;

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
            if (arguments.ContainsKey("/keysize"))
            {

                if (arguments["/keysize"].Equals("512") || arguments["/keysize"].Equals("1024") ||
                    arguments["/keysize"].Equals("2048") || arguments["/keysize"].Equals("4096") )
                {
                    keySize = Int32.Parse(arguments["/keysize"]);
                }
                else
                {
                    Console.WriteLine("[X] /keysize must be either 512, 1024, 2048 (default) or 4096");
                    return;
                    
                }
                
            }
            if (arguments.ContainsKey("/template"))
            {
                template = arguments["/template"];
            }

            if (arguments.ContainsKey("/subject"))
            {
                subject = arguments["/subject"];
            }

            if (arguments.ContainsKey("/altname"))
            {
                altName = arguments["/altname"];
            }

            if(arguments.ContainsKey("/sidextension"))
            {
                sidExtension = arguments["/sidextension"];
            }
            if (arguments.ContainsKey("/sid"))
            {
                sidExtension = arguments["/sid"];
            }

            if (arguments.ContainsKey("/install"))
            {
                install = true;
            }

            if (arguments.ContainsKey("/computer") || arguments.ContainsKey("/machine"))
            {
                if (template == "User")
                {
                    template = "Machine";
                }
                machineContext = true;
            }

            if (arguments.ContainsKey("/onbehalfof"))
            {
                if (!arguments.ContainsKey("/enrollcert") || String.IsNullOrEmpty(arguments["/enrollcert"]))
                {
                    Console.WriteLine("[X] /enrollcert parameter missing. Issued Enrollment/Certificates Request Agent certificate required!");
                    return;
                }

                var enrollCertPassword = arguments.ContainsKey("/enrollcertpw")
                    ? arguments["/enrollcertpw"]
                    : "";

                if (!arguments["/onbehalfof"].Contains("\\"))
                {
                    Console.WriteLine("[X] /onbehalfof format of DOMAIN\\USER required, you may need to specify \\\\ for escaping purposes");
                    return;
                }

                Cert.RequestCertOnBehalf(CA, template, arguments["/onbehalfof"], arguments["/enrollcert"], enrollCertPassword, machineContext,keySize);
            }
            else
            {
                Cert.RequestCert(CA, machineContext, template, subject, altName, sidExtension, install,keySize);
            }
        }
    }
}
