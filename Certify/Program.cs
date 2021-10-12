using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace Certify
{
    public class Program
    {
        public static void FileExecute(string commandName, Dictionary<string, string> parsedArgs)
        {
            // execute w/ stdout/err redirected to a file

            var file = parsedArgs["/outfile"];

            var realStdOut = Console.Out;
            var realStdErr = Console.Error;

            using (var writer = new StreamWriter(file, false))
            {
                writer.AutoFlush = true;
                Console.SetOut(writer);
                Console.SetError(writer);

                MainExecute(commandName, parsedArgs);

                Console.Out.Flush();
                Console.Error.Flush();
            }
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);
        }

        public static void MainExecute(string commandName, Dictionary<string, string> parsedArgs)
        {
            // main execution logic
            var sw = new Stopwatch();
            sw.Start();

            if(!(parsedArgs.ContainsKey("/quiet") || parsedArgs.ContainsKey("/q") || parsedArgs.ContainsKey("/json")))
                Info.ShowLogo();

            parsedArgs.Remove("/q");
            parsedArgs.Remove("/quiet");

            try
            {
                var commandFound = new CommandCollection().ExecuteCommand(commandName, parsedArgs);

                // show the usage if no commands were found for the command name
                if (commandFound == false)
                    Info.ShowUsage();
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled Certify exception:\r\n");
                Console.WriteLine(e);
            }

            sw.Stop();
            if(!parsedArgs.ContainsKey("/json"))
                Console.WriteLine("\r\n\r\nCertify completed in " + sw.Elapsed);
        }

        public static string MainString(string command)
        {
            // helper that executes an input string command and returns results as a string
            //  useful for PSRemoting execution

            var args = command.Split();

            var parsed = ArgumentParser.Parse(args);
            if (parsed.ParsedOk == false)
            {
                Info.ShowLogo();
                Info.ShowUsage();
                return "Error parsing arguments: ${command}";
            }

            var commandName = args.Length != 0 ? args[0] : "";

            var realStdOut = Console.Out;
            var realStdErr = Console.Error;
            TextWriter stdOutWriter = new StringWriter();
            TextWriter stdErrWriter = new StringWriter();
            Console.SetOut(stdOutWriter);
            Console.SetError(stdErrWriter);

            MainExecute(commandName, parsed.Arguments);

            Console.Out.Flush();
            Console.Error.Flush();
            Console.SetOut(realStdOut);
            Console.SetError(realStdErr);

            var output = "";
            output += stdOutWriter.ToString();
            output += stdErrWriter.ToString();

            return output;
        }

        public static void Main(string[] args)
        {
            try
            {
                var parsed = ArgumentParser.Parse(args);
                if (parsed.ParsedOk == false)
                {
                    Info.ShowLogo();
                    Info.ShowUsage();
                    return;
                }

                var commandName = args.Length != 0 ? args[0] : "";

                if (parsed.Arguments.ContainsKey("/outfile"))
                {
                    // redirect output to a file specified
                    FileExecute(commandName, parsed.Arguments);
                }
                else
                {
                    MainExecute(commandName, parsed.Arguments);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled Certify exception:\r\n");
                Console.WriteLine(e);
            }
        }
    }
}