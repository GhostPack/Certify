using Certify.Commands;
using Certify.Lib;
using CommandLine;
using CommandLine.Text;
using System;
using System.Diagnostics;
using System.IO;

namespace Certify
{
    internal class DefaultOptions
    {
        [Option("out-file", HelpText = "Redirect all output streams to a file (format: FILE-PATH)")]
        public string OutFile { get; set; }

        [Option("quiet", HelpText = "Omit printing the Certify logo")]
        public bool Quiet { get; set; }
    };

    internal class Program
    {
        public static string Version { get; } = "2.0.0";

        private static void ShowLogo()
        {
            Console.WriteLine();
            Console.WriteLine(@"   _____          _   _  __          ");
            Console.WriteLine(@"  / ____|        | | (_)/ _|         ");
            Console.WriteLine(@" | |     ___ _ __| |_ _| |_ _   _    ");
            Console.WriteLine(@" | |    / _ \ '__| __| |  _| | | |   ");
            Console.WriteLine(@" | |___|  __/ |  | |_| | | | |_| |   ");
            Console.WriteLine(@"  \_____\___|_|   \__|_|_|  \__, |   ");
            Console.WriteLine(@"                             __/ |   ");
            Console.WriteLine(@"                            |___./   ");
            Console.WriteLine($"  v{Version}                         ");
            Console.WriteLine();
        }

        private static ParserResult<object> ParserInitialize(string[] args)
        {
#if !DISARMED

            DistributedComUtil.Initialize();
            DistributedComUtil.InitializeSecurity();
#endif

            var parser = new Parser(settings =>
            {
                settings.AutoHelp = false;
                settings.AutoVersion = false;
                settings.HelpWriter = null;
            });

            return parser.ParseArguments<
                EnumCas.Options, 
                EnumTemplates.Options, 
                EnumPkiObjects.Options
#if !DISARMED
                , 
                CertRequest.Options, 
                CertRequestOnBehalf.Options,
                CertRequestDownload.Options,
                CertRequestRenewal.Options, 
                CertForge.Options, 
                ManageCa.Options, 
                ManageTemplate.Options, 
                ManageSelf.Options
#endif
                >(args);
        }

        private static int ParserFinalize(ParserResult<object> result)
        {
            return result.MapResult(
                (EnumCas.Options opts) => EnumCas.Execute(opts),
                (EnumTemplates.Options opts) => EnumTemplates.Execute(opts),
                (EnumPkiObjects.Options opts) => EnumPkiObjects.Execute(opts),
#if !DISARMED
                (CertRequest.Options opts) => CertRequest.Execute(opts),
                (CertRequestOnBehalf.Options opts) => CertRequestOnBehalf.Execute(opts),
                (CertRequestDownload.Options opts) => CertRequestDownload.Execute(opts),
                (CertRequestRenewal.Options opts) => CertRequestRenewal.Execute(opts),
                (CertForge.Options opts) => CertForge.Execute(opts),
                (ManageCa.Options opts) => ManageCa.Execute(opts),
                (ManageTemplate.Options opts) => ManageTemplate.Execute(opts),
                (ManageSelf.Options opts) => ManageSelf.Execute(opts),
#endif
                errors =>
                {
                    var help_text = HelpText.AutoBuild(result, h => {
                        h.AdditionalNewLineAfterOption = false;
                        h.AutoVersion = false;
                        h.AutoHelp = false;
                        h.Copyright = string.Empty;
                        h.Heading = string.Empty;
                        h.MaximumDisplayWidth = 100;
                        return HelpText.DefaultParsingErrorsHandler(result, h);
                    }, e => e);

                    Console.WriteLine(help_text);
                    return 1;
                }
            );
        }

        private static void MainExecute(ParserResult<object> result, DefaultOptions opts)
        {
            var sw = new Stopwatch();
            sw.Start();

            if (opts != null && !opts.Quiet)
                ShowLogo();

            ParserFinalize(result);

            sw.Stop();

            Console.WriteLine();
            Console.WriteLine("Certify completed in {0}", sw.Elapsed);
        }

        private static void FileExecute(ParserResult<object> result, DefaultOptions opts)
        {
            var stdout = Console.Out;
            var stderr = Console.Error;

            using (var sw = new StreamWriter(opts.OutFile, false) { AutoFlush = true })
            {
                try
                {
                    Console.SetOut(sw);
                    Console.SetError(sw);

                    MainExecute(result, opts);

                    Console.Out.Flush();
                    Console.Error.Flush();
                }
                finally
                {
                    Console.SetOut(stdout);
                    Console.SetError(stderr);
                }
            }
        }

        [MTAThread]
        public static void Main(string[] args)
        {
            try
            {
                var result = ParserInitialize(args);
                var opts = (DefaultOptions)result.Value;

                if (opts != null && !string.IsNullOrEmpty(opts.OutFile))
                    FileExecute(result, opts);
                else
                    MainExecute(result, opts);
            }
            catch (Exception e)
            {
                Console.WriteLine();
                Console.WriteLine("[!] Unhandled Certify exception:");
                Console.WriteLine();
                Console.WriteLine(e);
            }
        }

        [MTAThread]
        public static string MainString(string args)
        {
            var stdout = Console.Out;
            var stderr = Console.Error;

            using (var sw = new StringWriter())
            {
                try
                {
                    Console.SetOut(sw);
                    Console.SetError(sw);

                    Main(args.Split());

                    Console.Out.Flush();
                    Console.Error.Flush();
                }
                finally
                {
                    Console.SetOut(stdout);
                    Console.SetError(stderr);
                }

                return sw.ToString();
            }
        }
    }
}
