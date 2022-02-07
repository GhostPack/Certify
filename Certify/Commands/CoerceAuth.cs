using Certify.Lib;
using System;
using System.Collections.Generic;

namespace Certify.Commands
{
    class CoerceAuth : ICommand
    {

        public static string CommandName => "coerceauth";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Force the CA machine to perform an authentication to a remote server.");

            var CA = "";
            var remoteIP = "";

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
            if (arguments.ContainsKey("/target"))
            {
                remoteIP = arguments["/target"];
            }
            else
            {
                Console.WriteLine("[X] A /target:Target is required!");
                return;
            }

            ModifyConfigEntry.CoerceAuth(CA, remoteIP);

        }
    }
}
