using Certify.Domain;
using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

#if !DISARMED

namespace Certify.Commands
{
    internal class ManageTemplate
    {
        [Verb("manage-template", HelpText = "Manage a certificate template")]
        public class Options : DefaultOptions
        {
            [Option("template", Required = true, HelpText = "Target certificate template (format: NAME)")]
            public string CertificateTemplate { get; set; }

            [Option("template-domain", Required = false, HelpText = "Target domain (format: FQDN)")]
            public string Domain { get; set; }

            [Option("template-ldap-server", Required = false, HelpText = "Target LDAP server")]
            public string LdapServer { get; set; }

            [Option("owner", Group = "Action", HelpText = "Set the owner of the AD object (format: SID)")]
            public string Owner { get; set; }

            [Option("enroll", Group = "Action", HelpText = "Grant 'Enroll' rights (format: SID)")]
            public IEnumerable<string> ToggleEnroll { get; set; }

            [Option("write-property", Group = "Action", HelpText = "Toggle 'WriteProperty' rights (format: SID)")]
            public IEnumerable<string> ToggleWriteProperty { get; set; }

            [Option("write-owner", Group = "Action", HelpText = "Toggle 'WriteOwner' rights (format: SID)")]
            public IEnumerable<string> ToggleWriteOwner { get; set; }

            [Option("write-dacl", Group = "Action", HelpText = "Toggle 'WriteDacl' rights (format: SID)")]
            public IEnumerable<string> ToggleWriteDacl { get; set; }

            [Option("authorized-signatures", Group = "Action", HelpText = "Set authorized signatures attribute (format: NUMBER)")]
            public int? AuthorizedSignaturesRequired { get; set; }

            [Option("manager-approval", Group = "Action", HelpText = "Enable/disable manager approval")]
            public bool ToggleManagerApproval { get; set; }

            [Option("supply-subject", Group = "Action", HelpText = "Enable/disable 'Enrolle Supplies Request'")]
            public bool ToggleSupplySubject { get; set; }

            [Option("client-auth", Group = "Action", HelpText = "Enable/disable the 'Client Authentication' EKU")]
            public bool ToggleClientAuth { get; set; }

            [Option("pkinit-auth", Group = "Action", HelpText = "Enable/disable the 'PKINIT Client Authentication' EKU")]
            public bool TogglePkinitClientAuth { get; set; }

            [Option("smartcard-logon", Group = "Action", HelpText = "Enable/disable the 'Smartcard Logon' EKU")]
            public bool ToggleSmartcardLogon { get; set; }

            [Option("esc9", Group = "Action", HelpText = "Enable/disable ESC9")]
            public bool ToggleNoExtension { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Manage a certificate template");

            if (!string.IsNullOrEmpty(opts.Domain) && !opts.Domain.Contains('.'))
            {
                Console.WriteLine("[X] The 'domain' parameter is not a fully qualified domain name.");
                return 1;
            }

            if (!string.IsNullOrEmpty(opts.Owner) && !SidUtil.IsValidSid(opts.Owner))
            {
                Console.WriteLine("[X] The 'set-owner' parameter is of the format '<sid>'.");
                return 1;
            }

            foreach (var x in opts.ToggleEnroll.Concat(opts.ToggleWriteProperty).Concat(opts.ToggleWriteOwner).Concat(opts.ToggleWriteDacl))
            {
                if (!SidUtil.IsValidSid(x))
                {
                    Console.WriteLine("[X] A role toggle parameter is not of the format '<sid>'.");
                    return 1;
                }
            }

            var ldap = new LdapOperations(opts.Domain, opts.LdapServer);

            Console.WriteLine($"[*] Using the search base '{ldap.ConfigurationPath}'");

            var template = ldap.GetCertificateTemplateEntry(opts.CertificateTemplate);

            if (template == null)
            {
                Console.WriteLine();
                Console.WriteLine("[X] The target certificate template could not be identified.");
            }
            else
            {
                PerformRightsModifications(opts, template);
                PerformDirectAttributeModifications(opts, template);
                PerformToggleCertificateNameFlag(opts, template);
                PerformToggleEnrollmentFlag(opts, template);
                PerformToggleEkus(opts, template);
            }

            return 0;
        }

        private static void PerformRightsModifications(Options opts, DirectoryEntry template)
        {
            var rights_modifications = new Dictionary<Tuple<string, Guid>, ActiveDirectoryRights>();

            void AddRightModifications(IEnumerable<string> sids, Guid type, ActiveDirectoryRights right)
            {
                foreach (var x in sids)
                    rights_modifications.Add(new Tuple<string, Guid>(x, type), right);
            }

            AddRightModifications(opts.ToggleEnroll, Guid.Parse("0e10c968-78fb-11d2-90d4-00c04f79dc55"), ActiveDirectoryRights.ExtendedRight);
            AddRightModifications(opts.ToggleWriteOwner, Guid.Empty, ActiveDirectoryRights.WriteOwner);
            AddRightModifications(opts.ToggleWriteDacl, Guid.Empty, ActiveDirectoryRights.WriteDacl);
            AddRightModifications(opts.ToggleWriteProperty, Guid.Empty, ActiveDirectoryRights.WriteProperty);

            if (!string.IsNullOrEmpty(opts.Owner) || (rights_modifications != null && rights_modifications.Any()))
            {
                Console.WriteLine();
                Console.WriteLine("[*] Attempting to toggle security permissions on the CA.");

                var rules = from ActiveDirectoryAccessRule rule in template.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier)) select rule;

                if (!string.IsNullOrEmpty(opts.Owner))
                    template.ObjectSecurity.SetOwner(new SecurityIdentifier(opts.Owner));
                
                // Key = Tuple<SID <string>, Object Type <string>>, Value = Rights <uint>
                foreach (var x in rights_modifications)
                {
                    var rule = rules.Where(r => r.IdentityReference.Value.Equals(x.Key.Item1, StringComparison.OrdinalIgnoreCase) && r.ObjectType == x.Key.Item2 && r.AccessControlType == AccessControlType.Allow);

                    // For enrollment right, if no ACE exists with the specific object type, try the default object type
                    if (x.Key.Item2 != Guid.Empty && (rule == null || !rule.Any()))
                        rule = rules.Where(r => r.IdentityReference.Value.Equals(x.Key.Item1, StringComparison.OrdinalIgnoreCase) && r.ObjectType == Guid.Empty && r.AccessControlType == AccessControlType.Allow);

                    if (rule != null && rule.Any())
                    {
                        foreach (var r in rule)
                        {
                            var new_rights = r.ActiveDirectoryRights ^ x.Value;

                            if (new_rights == 0)
                                template.ObjectSecurity.RemoveAccess(r.IdentityReference, r.AccessControlType);
                            else
                            {
                                template.ObjectSecurity.SetAccessRule(new ActiveDirectoryAccessRule(r.IdentityReference,
                                    new_rights, r.AccessControlType, r.ObjectType, r.InheritanceType, r.InheritedObjectType));
                            }
                        }
                    }
                    else
                    {
                        template.ObjectSecurity.SetAccessRule(new ActiveDirectoryAccessRule(new SecurityIdentifier(x.Key.Item1.ToUpper()), x.Value, AccessControlType.Allow, x.Key.Item2));
                    }
                }

                try
                {
                    template.CommitChanges();
                    Console.WriteLine("[*] Successfully modified the certificate template.");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to modify the certificate template object: {e.Message}.");
                }
            }
        }

        private static void PerformDirectAttributeModifications(Options opts, DirectoryEntry template)
        {
            if (opts.AuthorizedSignaturesRequired.HasValue)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Attempting to set the authorized signatures on the certificate template.");

                template.Properties["msPKI-RA-Signature"].Value = opts.AuthorizedSignaturesRequired.Value;

                try
                {
                    template.CommitChanges();
                    Console.WriteLine("[*] Successfully modified the certificate template.");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to modify the certificate template object: {e.Message}.");
                }
            }
        }

        private static void PerformToggleCertificateNameFlag(Options opts, DirectoryEntry template)
        {
            if (opts.ToggleSupplySubject)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Attempting to toggle certificate name flags on the certificate template.");

                var flag_mod = msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT;

                var flag_str = template.Properties["msPKI-Certificate-Name-Flag"].Value.ToString();
                var flag_val = LdapParser.ParseIntToEnum<msPKICertificateNameFlag>(flag_str);

                template.Properties["msPKI-Certificate-Name-Flag"].Value = (int)(flag_val ^ flag_mod);

                try
                {
                    template.CommitChanges();
                    Console.WriteLine("[*] Successfully modified the certificate template.");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to modify the certificate template object: {e.Message}.");
                }
            }
        }

        private static void PerformToggleEnrollmentFlag(Options opts, DirectoryEntry template)
        {
            if (opts.ToggleManagerApproval || opts.ToggleNoExtension)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Attempting to toggle enrollment flags on the certificate template.");

                var flag_mod = msPKIEnrollmentFlag.NONE;

                if (opts.ToggleManagerApproval)
                    flag_mod |= msPKIEnrollmentFlag.PEND_ALL_REQUESTS;

                if (opts.ToggleNoExtension)
                    flag_mod |= msPKIEnrollmentFlag.NO_SECURITY_EXTENSION;

                var flag_str = template.Properties["msPKI-Enrollment-Flag"].Value.ToString();
                var flag_val = LdapParser.ParseIntToEnum<msPKIEnrollmentFlag>(flag_str);

                template.Properties["msPKI-Enrollment-Flag"].Value = (int)(flag_val ^ flag_mod);

                try
                {
                    template.CommitChanges();
                    Console.WriteLine("[*] Successfully modified the certificate template.");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to modify the certificate template object: {e.Message}.");
                }
            }
        }

        private static void PerformToggleEkus(Options opts, DirectoryEntry template)
        {
            if (opts.ToggleClientAuth || opts.TogglePkinitClientAuth || opts.ToggleSmartcardLogon)
            {
                Console.WriteLine();
                Console.WriteLine("[*] Attempting to toggle targeted EKUs on the certificate template.");

                void toggle_oid(string oid)
                {
                    if (template.Properties["pkiExtendedKeyUsage"].Contains(oid))
                        template.Properties["pkiExtendedKeyUsage"].Remove(oid);
                    else
                        template.Properties["pkiExtendedKeyUsage"].Add(oid);

                    template.Properties["msPKI-Certificate-Application-Policy"].Clear();
                    template.Properties["msPKI-Certificate-Application-Policy"].AddRange(template.Properties["pkiExtendedKeyUsage"]);
                }

                if (opts.ToggleClientAuth)
                    toggle_oid(CommonOids.ClientAuthentication);

                if (opts.TogglePkinitClientAuth)
                    toggle_oid(CommonOids.PKINITClientAuthentication);

                if (opts.ToggleSmartcardLogon)
                    toggle_oid(CommonOids.SmartcardLogon);

                try
                {
                    template.CommitChanges();
                    Console.WriteLine("[*] Successfully modified the certificate template.");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to modify the certificate template object: {e.Message}.");
                }
            }
        }
    }
}

#endif