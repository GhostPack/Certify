using Certify.Lib;
using System;
using System.Collections.Generic;

namespace Certify.Commands
{
    class SetConfig : ICommand
    {

        public static string CommandName => "setconfig";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Modify the CA persistent settings.");

            var CA = "";
            var restart = false;
            var enableSAN = false;
            var removeApproval = false;

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

            if (arguments.ContainsKey("/enablesan"))
            {
                enableSAN = true;
            }
            
            if (arguments.ContainsKey("/removeapproval"))
            {
                removeApproval = true;
            }

            if (arguments.ContainsKey("/restart"))
            {
                restart = true;
            }

            ModifyConfigEntry.ModifyEntry(CA, enableSAN, removeApproval,restart);

        }
    }
}
