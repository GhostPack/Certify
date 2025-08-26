using Certify.Domain;
using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;

namespace Certify.Commands
{
    internal class EnumCas
    {
        [Verb("enum-cas", HelpText = "Enumerate certificate authorities")]
        public class Options : DefaultOptions
        {
            [Option("ca", HelpText = "Target certificate authority")]
            public string CertificateAuthority { get; set; }

            [Option("domain", HelpText = "Target domain")]
            public string Domain { get; set; }

            [Option("ldap-server", HelpText = "Target LDAP server")]
            public string LdapServer { get; set; }

            [Option("current-user", SetName = "MarkCurrentUser", HelpText = "Mark vulnerabilities as current user")]
            public bool CurrentUser { get; set; }

            [Option("target-user", SetName = "MarkTargetUser", HelpText = "Mark vulnerabilities as target user")]
            public string TargetUser { get; set; }

            [Option("filter-vulnerable", HelpText = "Show only vulnerable CAs")]
            public bool FilterVulnerable { get; set; }

            [Option("hide-admins",  HelpText = "Exclude admin permissions")]
            public bool HideAdmins { get; set; }

            [Option("show-all-perms", HelpText = "Show all permission details")]
            public bool ShowAllPermissions { get; set; }

            [Option("skip-web-checks", HelpText = "Skip web service checks")]
            public bool SkipWebServiceChecks { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Find certificate authorities");

            if (!string.IsNullOrEmpty(opts.CertificateAuthority) && !opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] The 'certificate authority' parameter is not of the format 'SERVER\\CA-NAME'.");
                return 1;
            }

            if (!string.IsNullOrEmpty(opts.Domain) && !opts.Domain.Contains('.'))
            {
                Console.WriteLine("[X] The 'domain' parameter is not a fully qualified domain name.");
                return 1;
            }

            var ldap = new LdapOperations(opts.Domain, opts.LdapServer);

            Console.WriteLine($"[*] Using the search base '{ldap.ConfigurationPath}'");

            List<string> user_sids = null;

            if (opts.CurrentUser)
            {
                var self = WindowsIdentity.GetCurrent();

                Console.WriteLine($"[*] Classifying vulnerabilities in the context of the current user ('{self.Name}') and its unrolled groups.");

                user_sids = self.Groups.Select(x => x.ToString()).ToList();
                user_sids.Add($"{self.User}");
            }
            else if (!string.IsNullOrEmpty(opts.TargetUser))
            {
                using (var domain = new PrincipalContext(ContextType.Domain, opts.Domain))
                {
                    using (var user = UserPrincipal.FindByIdentity(domain, opts.TargetUser))
                    {
                        if (user == null)
                        {
                            if (string.IsNullOrEmpty(opts.Domain))
                                Console.WriteLine($"[!] Could not find user '{opts.TargetUser}' in current domain.");
                            else
                                Console.WriteLine($"[!] Could not find user '{opts.TargetUser}' in domain '{opts.Domain}'.");
                        }
                        else
                        {
                            using (var user_identity = new WindowsIdentity(user.UserPrincipalName))
                            {
                                Console.WriteLine($"[*] Classifying vulnerabilities in the context of the target user ('{user_identity.Name}') and its unrolled groups.");

                                user_sids = user_identity.Groups.Select(x => x.ToString()).ToList();
                                user_sids.Add($"{user_identity.User}");
                            }
                        }
                    }
                }
            }

            if (user_sids == null)
                Console.WriteLine($"[*] Classifying vulnerabilities in the context of built-in low-privileged domain groups.");

            PrintRootCAs(ldap);
            PrintNtAuthCertificates(ldap);
            PrintEnterpriseCAs(opts, ldap, user_sids);

            return 0;
        }

        private static void PrintRootCAs(LdapOperations ldap)
        {
            Console.WriteLine();
            Console.WriteLine("[*] Root CAs");

            var root_cas = ldap.GetRootCAs();

            if (root_cas == null) 
                throw new NullReferenceException("RootCAs are null");
            else
            {
                foreach (var ca in root_cas)
                {
                    if (ca.Certificates != null)
                    {
                        foreach (var cert in ca.Certificates)
                        {
                            Console.WriteLine();
                            DisplayUtil.PrintCertificateInfo(cert);
                        }
                    }
                }
            }
        }

        private static void PrintNtAuthCertificates(LdapOperations ldap)
        {
            Console.WriteLine();
            Console.WriteLine("[*] NTAuthCertificates - Certificates that enable authentication:");

            var ntauth = ldap.GetNtAuthCertificates();

            if (ntauth.Certificates == null || !ntauth.Certificates.Any())
            {
                Console.WriteLine();
                Console.WriteLine("    There are no NTAuthCertificates");
            }
            else
            {
                foreach (var cert in ntauth.Certificates)
                {
                    Console.WriteLine();
                    DisplayUtil.PrintCertificateInfo(cert);
                }
            }
        }

        private static void PrintEnterpriseCAs(Options opts, LdapOperations ldap, List<string> user_sids)
        {
            var cas = ldap.GetEnterpriseCAs(opts.CertificateAuthority, user_sids);

            if (opts.FilterVulnerable)
                cas = cas.Where(ca => ca.Vulnerabilities != null && ca.Vulnerabilities.Any());

            if (!cas.Any())
            {
                Console.WriteLine();
                Console.WriteLine("[+] No enterprise certificate authorities found with the current filter parameters.");
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[*] Enterprise/enrollment certificate authorities:");

                foreach (var ca in cas)
                {
                    Console.WriteLine();
                    DisplayUtil.PrintEnterpriseCaInfo(ca, opts.HideAdmins, opts.ShowAllPermissions);

                    if (!opts.SkipWebServiceChecks)
                        PrintCAWebServices(ca.GetWebServices());

                    Console.WriteLine("    Enabled Certificate Templates:");

                    if (ca.Templates == null || !ca.Templates.Any())
                        Console.WriteLine("        There are no enabled Certificate Templates");
                    else
                        Console.WriteLine("        " + string.Join("\n        ", ca.Templates));
                }
            }
        }

        private static void PrintCAWebServices(CertificateAuthorityWebServices web_services)
        {
            var join_sep = $"\n{new string(' ', 36)}";

            if (web_services.LegacyAspEnrollmentUrls.Any())
            {
                Console.WriteLine($"    Legacy ASP Enrollment Website : {string.Join(join_sep, web_services.LegacyAspEnrollmentUrls)}");
                Console.WriteLine();
            }

            if (web_services.EnrollmentWebServiceUrls.Any())
            { 
                Console.WriteLine($"    Enrollment Web Service        : {string.Join(join_sep, web_services.EnrollmentWebServiceUrls)}");
                Console.WriteLine();
            }

            if (web_services.EnrollmentPolicyWebServiceUrls.Any())
            {
                Console.WriteLine($"    Enrollment Policy Web Service : {string.Join(join_sep, web_services.EnrollmentPolicyWebServiceUrls)}");
                Console.WriteLine();
            }

            if (web_services.NetworkDeviceEnrollmentServiceUrls.Any())
            {
                Console.WriteLine($"    NDES Web Service              : {string.Join(join_sep, web_services.NetworkDeviceEnrollmentServiceUrls)}");
                Console.WriteLine();
            }
        }
    }
}
