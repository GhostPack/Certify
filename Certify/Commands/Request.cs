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
            var url = "";
            var sidExtension = "";
            var template = "User";
            var machineContext = false;
            var install = false;

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

            if (arguments.ContainsKey("/url"))
            {
                url = arguments["/url"];
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

                Cert.RequestCertOnBehalf(CA, template, arguments["/onbehalfof"], arguments["/enrollcert"], enrollCertPassword, machineContext);
            }
            else
            {
                Cert.RequestCert(CA, machineContext, template, subject, altName, url, sidExtension, install);
            }
        }
    }
}