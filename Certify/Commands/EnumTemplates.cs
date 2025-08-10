using Certify.Domain;
using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Security.Principal;

namespace Certify.Commands
{
    internal class EnumTemplates
    {
        [Verb("enum-templates", HelpText = "Enumerate certificate templates")]
        public class Options : DefaultOptions
        {
            [Option("ca", HelpText = "Target certificate authority (format: SERVER\\CA-NAME)")]
            public string CertificateAuthority { get; set; }

            [Option("template", HelpText = "Target certificate template (format: NAME)")]
            public string CertificateTemplate { get; set; }

            [Option("domain", HelpText = "Target domain (format: FQDN)")]
            public string Domain { get; set; }

            [Option("ldap-server", HelpText = "Target LDAP server")]
            public string LdapServer { get; set; }

            [Option("current-user", SetName = "MarkCurrentUser", HelpText = "Mark vulnerabilities as current user")]
            public bool CurrentUser { get; set; }

            [Option("target-user", SetName = "MarkTargetUser", HelpText = "Mark vulnerabilities as target principal")]
            public string TargetUser { get; set; }

            [Option("filter-enabled", HelpText = "Show only enabled templates")]
            public bool FilterEnabled { get; set; }

            [Option("filter-vulnerable", HelpText = "Show only vulnerable templates")]
            public bool FilterVulnerable { get; set; }

            [Option("filter-request-agent", HelpText = "Show only 'on-behalf-of' templates")]
            public bool FilterRequestAgent { get; set; }

            [Option("filter-client-auth", HelpText = "Show only 'client auth' templates")]
            public bool FilterClientAuth { get; set; }

            [Option("filter-supply-subject", HelpText = "Show only 'subject in request' templates")]
            public bool FilterEnrolleeSuppliesSubject { get; set; }

            [Option("filter-manager-approval", HelpText = "Show only 'manager approval' templates")]
            public bool FilterManagerApproval { get; set; }

            [Option("hide-admins", HelpText = "Exclude admin permissions")]
            public bool HideAdmins { get; set; }

            [Option("show-all-perms", HelpText = "Show all permission details")]
            public bool ShowAllPermissions { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Find certificate templates");

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

            if (!string.IsNullOrEmpty(opts.CertificateAuthority))
                Console.WriteLine($"[*] Restricting to CA name : {opts.CertificateAuthority}");

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

            var cas = ldap.GetEnterpriseCAs(opts.CertificateAuthority, user_sids);
            var templates = ldap.GetCertificateTemplates(user_sids);

            if (!cas.Any())
                Console.WriteLine("[!] Could not identify any enterprise certificate authorities.");
            else if (!templates.Any())
                Console.WriteLine("[!] Could not identify any certificate templates.");
            else
            {
                var valid_templates = new List<CertificateTemplate>();

                foreach (var template in templates)
                {
                    if (template.Name == null)
                        Console.WriteLine($"[!] Warning: Unable to get the name of the template '{template.DistinguishedName}'.");
                    else if (template.SecurityDescriptor == null)
                        Console.WriteLine($"[!] Warning: Unable to get the security descriptor for the template '{template.DistinguishedName}'.");
                    else
                        valid_templates.Add(template);
                }

                var valid_cas = new List<CertificateAuthorityEnterprise>();

                foreach (var ca in cas)
                {
                    Console.WriteLine();
                    Console.WriteLine($"[*] Listing info about the enterprise certificate authority '{ca.Name}'");
                    Console.WriteLine();

                    DisplayUtil.PrintEnterpriseCaInfo(ca, opts.HideAdmins, opts.ShowAllPermissions);

                    if (ca.Templates == null)
                        Console.WriteLine($"[!] Warning: Unable to get a list of published certificate templates on certificate authority '{ca.DistinguishedName}'.");
                    else
                    {
                        valid_cas.Add(ca);

                        // Published templates that does not exist in the template stack cannot be read by the current user
                        var unreadable_templates = ca.Templates.Where(n => !valid_templates.Any(t => t.Name == n));

                        if (unreadable_templates.Any())
                        {
                            Console.WriteLine($"[!] The enterprise certificate authority '{ca.Name}' publishes the following unreadable certificate templates:");
                            Console.WriteLine();
                            Console.WriteLine($"    {string.Join("\n    ", unreadable_templates)}");
                            Console.WriteLine();
                        }
                    }
                }

                if (!string.IsNullOrEmpty(opts.CertificateTemplate))
                {
                    valid_templates = valid_templates
                        .Where(t => t.Name == opts.CertificateTemplate)
                        .ToList();
                }

                if (opts.FilterManagerApproval)
                {
                    valid_templates = valid_templates
                        .Where(t => t.EnrollmentFlag.HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS))
                        .ToList();
                }

                if (opts.FilterRequestAgent)
                {
                    valid_templates = valid_templates
                        .Where(t => t.SchemaVersion == 1 || (t.SchemaVersion >= 2 && t.RaApplicationPolicies != null && t.RaApplicationPolicies.Contains(CommonOids.CertificateRequestAgent)))
                        .ToList();
                }

                if (opts.FilterClientAuth)
                {
                    var auth_oids = new List<string>()
                    {
                        CommonOids.ClientAuthentication,
                        CommonOids.PKINITClientAuthentication,
                        CommonOids.SmartcardLogon,
                        CommonOids.AnyPurpose
                    };

                    valid_templates = valid_templates
                        .Where(t => t.ExtendedKeyUsage == null || t.ExtendedKeyUsage.Any(o => auth_oids.Contains(o)))
                        .ToList();
                }

                if (opts.FilterEnrolleeSuppliesSubject)
                {
                    valid_templates = valid_templates
                        .Where(t => t.CertificateNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT))
                        .ToList();
                }

                if (opts.FilterVulnerable)
                {
                    valid_templates = valid_templates
                        .Where(t => t.Vulnerabilities != null && t.Vulnerabilities.Any())
                        .ToList();
                }

                if (opts.FilterEnabled)
                {
                    valid_templates = valid_templates
                        .Where(t => valid_cas.Any(ca => ca.Templates.Contains(t.Name)))
                        .ToList();
                }

                if (!valid_templates.Any())
                {
                    Console.WriteLine("[+] No certificates templates found with the current filter parameters.");
                }
                else
                {
                    Console.WriteLine("[*] Certificate templates found using the current filter parameters:");

                    foreach (var template in valid_templates)
                    {
                        var enabled_cas = valid_cas.Where(ca => ca.Templates.Contains(template.Name));
                        DisplayUtil.PrintCertificateTemplateInfo(enabled_cas, template, opts.HideAdmins, opts.ShowAllPermissions);
                    }
                }
            }

            return 0;
        }
    }
}
