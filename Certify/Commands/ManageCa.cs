using Certify.Domain;
using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text.RegularExpressions;

#if !DISARMED

namespace Certify.Commands
{
    internal class ManageCa
    {
        [Verb("manage-ca", HelpText = "Manage a certificate authority")]
        public class Options : DefaultOptions
        {
            [Option("ca", Required = true, HelpText = "Target certificate authority (format: SERVER\\CA-NAME)")]
            public string CertificateAuthority { get; set; }

            [Option("template", Group = "Action", HelpText = "Enable/disable a certificate template (format: NAME)")]
            public IEnumerable<string> ToggleTemplates { get; set; }

            [Option("template-domain", Required = false, HelpText = "Target domain (format: FQDN)")]
            public string Domain { get; set; }

            [Option("template-ldap-server", Required = false, HelpText = "Target LDAP server")]
            public string LdapServer { get; set; }

            [Option("issue-id", Group = "Action", HelpText = "Issue a certificate request (format: ID)")]
            public IEnumerable<uint> IssueRequestIds { get; set; }

            [Option("deny-id", Group = "Action", HelpText = "Deny a certificate request (format: ID)")]
            public IEnumerable<uint> DenyRequestIds { get; set; }

            [Option("revoke-cert", Group = "Action", HelpText = "Revoke a certificate (format: SERIAL-NUMBER)")]
            public IEnumerable<string> RevokeCertificates { get; set; }

            [Option("issuance-policy", Group = "Action", HelpText = "Set issuance policy (format: REQUEST-ID:OID)")]
            public IEnumerable<string> IssuancePolicies { get; set; }

            [Option("application-policy", Group = "Action", HelpText = "Set application policy (format: REQUEST-ID:OID)")]
            public IEnumerable<string> ApplicationPolicies { get; set; }

            [Option("enroll", Group = "Action", HelpText = "Toggle 'Enroll' role (format: SID)")]
            public IEnumerable<string> ToggleEnroll { get; set; }

            [Option("officer", Group = "Action", HelpText = "Toggle 'ManageCertificates' role (format: SID)")]
            public IEnumerable<string> ToggleManageCertificates { get; set; }

            [Option("admin", Group = "Action", HelpText = "Toggle 'ManageCA' role (format: SID)")]
            public IEnumerable<string> ToggleManageCa { get; set; }

            [Option("esc6", Group = "Action", HelpText = "Enable/disable ESC6")]
            public bool ToggleCaSan { get; set; }

            [Option("esc11", Group = "Action", HelpText = "Enable/disable ESC11")]
            public bool ToggleRpcEncryption { get; set; }

            [Option("esc16", Group = "Action", HelpText = "Enable/disable ESC16")]
            public bool ToggleNoExtension { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Manage a certificate authority");

            if (!opts.CertificateAuthority.Contains("\\"))
            {
                Console.WriteLine("[X] The 'certificate authority' parameter is not of the format 'SERVER\\CA-NAME'.");
                return 1;
            }

            var parts = opts.CertificateAuthority.Split('\\');

            if (string.IsNullOrEmpty(parts[0]))
            {
                Console.WriteLine("[X] The 'SERVER' part of the certificate authority parameter is malformed.");
                return 1;
            }

            if (string.IsNullOrEmpty(parts[1]))
            {
                Console.WriteLine("[X] The 'CA-NAME' part of the certificate authority parameter is malformed.");
                return 1;
            }

            foreach (var x in opts.IssuancePolicies.Concat(opts.ApplicationPolicies))
            {
                if (!Regex.IsMatch(x, @"^\d+:\d+(\.\d+)*$", RegexOptions.IgnoreCase))
                {
                    Console.WriteLine("[X] A policy parameter is not of the format '<request-id>:<policy oid>'.");
                    return 1;
                }
            }

            foreach (var x in opts.ToggleEnroll.Concat(opts.ToggleManageCertificates).Concat(opts.ToggleManageCa))
            {
                if (!SidUtil.IsValidSid(x))
                {
                    Console.WriteLine("[X] A role toggle parameter is not of the format '<sid>'.");
                    return 1;
                }
            }

            var server = parts[0];
            var authority = parts[1];

            PerformTemplateModifications(opts, server, authority);
            PerformCertificateActions(opts, server, authority);
            PerformCertificateModifications(opts, server, authority);
            PerformRoleModifications(opts, server, authority);
            PerformFlagToggles(opts, server, authority);

            return 0;
        }

        private static void PerformTemplateModifications(Options opts, string server, string authority)
        {
            if (opts.ToggleTemplates.Any())
            {
                Console.WriteLine();
                Console.WriteLine("[*] Attempting to modify published templates on the CA.");

                if (!CertAdmin.GetTemplates(server, authority, out string templates))
                    Console.WriteLine("[X] Failed to query a list of published certificate templates from the CA.");
                else
                {
                    var parts = templates.Split('\n');
                    var template_pairs = new List<Tuple<string, string>>(); // Item1 = Name, Item2 = Oid

                    for (var i = 0; i < parts.Length - 1; i += 2)
                        template_pairs.Add(new Tuple<string, string>(parts[i], parts[i + 1]));

                    var add_templates = opts.ToggleTemplates.Except(template_pairs.Select(t => t.Item1), StringComparer.OrdinalIgnoreCase).ToList();
                    var deleted_temps = template_pairs.RemoveAll(t => opts.ToggleTemplates.Contains(t.Item1, StringComparer.OrdinalIgnoreCase));

                    var ldap = new LdapOperations(opts.Domain, opts.LdapServer);
                    var ldap_temps = ldap.GetCertificateTemplates().Where(t => t.Name != null);

                    var unidentified = add_templates.Where(t => !ldap_temps.Any(x => t.Equals(x.Name, StringComparison.OrdinalIgnoreCase))).ToList();

                    if (unidentified.Any())
                    {
                        Console.WriteLine("[!] Could not identify the following template names:");
                        Console.WriteLine($"    {string.Join("\n    ", unidentified)}");
                    }

                    if (deleted_temps == 0 && unidentified.Count == add_templates.Count)
                        Console.WriteLine("[*] No published certificate template modifications were made.");
                    else
                    {
                        foreach (var template in ldap_temps)
                        {
                            if (add_templates.Contains(template.Name, StringComparer.OrdinalIgnoreCase))
                                template_pairs.Insert(0, new Tuple<string, string>(template.Name, template.Oid.Value));
                        }

                        Console.WriteLine($"[*] Attempting to save a list of published certificate templates on the CA.");
                        Console.WriteLine($"    {string.Join("\n    ", template_pairs.Select(x => x.Item1))}");

                        templates = string.Join("", template_pairs.Select(x => $"{x.Item1}\n{x.Item2}\n"));

                        if (CertAdmin.SetTemplates(server, authority, templates))
                            Console.WriteLine("[+] Successfully set the list of published certificate templates on the CA.");
                        else
                            Console.WriteLine("[X] Failed to set the list of published certificate templates on the CA.");
                    }
                }
            }
        }

        private static void PerformCertificateActions(Options opts, string server, string authority)
        {
            if (opts.IssueRequestIds.Any())
            {
                Console.WriteLine();

                foreach (var request_id in opts.IssueRequestIds)
                {
                    Console.WriteLine($"[*] Attempting to issue certificate request with ID = '{request_id}'.");
                    CertAdmin.IssueRequest(server, authority, request_id);
                }
            }

            if (opts.DenyRequestIds.Any())
            {
                Console.WriteLine();

                foreach (var request_id in opts.DenyRequestIds)
                {
                    Console.WriteLine($"[*] Attempting to deny certificate request with ID = '{request_id}'.");

                    if (CertAdmin.DenyRequest(server, authority, request_id))
                        Console.WriteLine($"[+] Successfully denied certificate request with ID = '{request_id}'.");
                    else
                        Console.WriteLine($"[X] Failed to deny certificate request with ID = '{request_id}'.");
                }
            }

            if (opts.RevokeCertificates.Any())
            {
                Console.WriteLine();

                foreach (var serial_number in opts.RevokeCertificates)
                {
                    Console.WriteLine($"[*] Attempting to revoke certificate with serial number = '{serial_number}'.");

                    if (CertAdmin.RevokeCertificate(server, authority, serial_number))
                        Console.WriteLine($"[+] Successfully revoked certificate with serial number = '{serial_number}'.");
                    else
                        Console.WriteLine($"[X] Failed to revoke certificate with serial number = '{serial_number}'.");
                }
            }
        }

        private static void PerformCertificateModifications(Options opts, string server, string authority)
        {
            if (opts.IssuancePolicies != null && opts.IssuancePolicies.Any())
            {
                Console.WriteLine();
                Console.WriteLine($"[*] Attempting to set issuance policies for targeted certificate requests.");

                foreach (var x in opts.IssuancePolicies.Select(s => s.Split(':')).GroupBy(s => s[0], s => s[1], (k, g) => new { Key = k, Group = g }))
                {
                    var policy_bytes = CertEnrollment.CreateIssuancePolicyExtensionRaw(x.Group.ToArray());

                    if (!uint.TryParse(x.Key, out uint request_id))
                        Console.WriteLine($"[X] Failed to convert '{x.Key}' to a <uint> type.");
                    else if (CertAdmin.SetExtension(server, authority, request_id, CommonOids.CertificatePolicies, true, policy_bytes))
                        Console.WriteLine($"[+] Successfully set issuance policies for certificate request with ID = '{request_id}'.");
                    else
                        Console.WriteLine($"[X] Failed to set issuance policies for certificate request with ID = '{request_id}'.");
                }
            }

            if (opts.ApplicationPolicies != null && opts.ApplicationPolicies.Any())
            {
                Console.WriteLine();
                Console.WriteLine($"[*] Attempting to set application policies for targeted certificate requests.");

                foreach (var x in opts.ApplicationPolicies.Select(s => s.Split(':')).GroupBy(s => s[0], s => s[1], (k, g) => new { Key = k, Group = g }))
                {
                    var policy_bytes = CertEnrollment.CreateApplicationPolicyExtensionRaw(x.Group.ToArray());

                    if (!uint.TryParse(x.Key, out uint request_id))
                        Console.WriteLine($"[X] Failed to convert '{x.Key}' to a <uint> type.");
                    else if (CertAdmin.SetExtension(server, authority, request_id, CommonOids.ApplicationPolicies, true, policy_bytes))
                        Console.WriteLine($"[+] Successfully set application policies for certificate request with ID = '{request_id}'.");
                    else
                        Console.WriteLine($"[X] Failed to set application policies for certificate request with ID = '{request_id}'.");
                }
            }
        }

        private static void PerformRoleModifications(Options opts, string server, string authority)
        {
            if (opts.ToggleEnroll.Any() || opts.ToggleManageCertificates.Any() || opts.ToggleManageCa.Any())
            {
                var role_modifications = new Dictionary<string, ActiveDirectoryRights>();

                void AddRoleModifications(IEnumerable<string> sids, CertificationAuthorityRights right)
                {
                    foreach (var x in sids)
                        role_modifications.Add(x, (ActiveDirectoryRights)right);
                }

                AddRoleModifications(opts.ToggleEnroll, CertificationAuthorityRights.Enroll);
                AddRoleModifications(opts.ToggleManageCertificates, CertificationAuthorityRights.ManageCertificates);
                AddRoleModifications(opts.ToggleManageCa, CertificationAuthorityRights.ManageCA);

                if (role_modifications.Any())
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Attempting to toggle role permissions on the CA.");

                    if (!CertAdmin.GetCASecurity(server, authority, out ActiveDirectorySecurity security_descriptor))
                        Console.WriteLine("[X] Failed to query the security descriptor of the CA.");
                    else
                    {
                        var rules = from ActiveDirectoryAccessRule rule in security_descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)) select rule;

                        // Key = SID <string>, Value = Rights <uint>
                        foreach (var x in role_modifications)
                        {
                            var rule = rules.Where(r => r.IdentityReference.Value.Equals(x.Key, StringComparison.OrdinalIgnoreCase));

                            if (rule != null && rule.Any())
                            {
                                foreach (var r in rule)
                                {
                                    Console.WriteLine($"[*] Toggling the '{(CertificationAuthorityRights)x.Value}' roles for principal '{x.Key.ToUpper()}'.");

                                    var new_rights = r.ActiveDirectoryRights ^ x.Value;

                                    if (new_rights == 0)
                                        security_descriptor.RemoveAccess(r.IdentityReference, r.AccessControlType);
                                    else
                                    {
                                        security_descriptor.SetAccessRule(new ActiveDirectoryAccessRule(r.IdentityReference,
                                            new_rights, r.AccessControlType, r.ObjectType, r.InheritanceType, r.InheritedObjectType));
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine($"[*] The principal '{x.Key.ToUpper()}' does not have any roles, granting '{(CertificationAuthorityRights)x.Value}'.");
                                security_descriptor.SetAccessRule(new ActiveDirectoryAccessRule(new SecurityIdentifier(x.Key.ToUpper()), x.Value, AccessControlType.Allow));
                            }
                        }

                        if (CertAdmin.SetCASecurity(server, authority, security_descriptor))
                            Console.WriteLine("[+] Successfully set the security descriptor on the CA.");
                        else
                            Console.WriteLine("[X] Failed to set the security descriptor on the CA.");
                    }
                }
            }
        }

        private static void PerformFlagToggles(Options opts, string server, string authority)
        {
            if (opts.ToggleCaSan || opts.ToggleRpcEncryption || opts.ToggleNoExtension)
            {
                if (opts.ToggleCaSan)
                {
                    Console.WriteLine();
                    Console.WriteLine($"[*] Attempting to toggle EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) on the CA.");

                    if (!CertAdmin.GetConfigEntry(server, authority, "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", out int flags))
                        Console.WriteLine("[X] Failed to retrieve the EditFlags configuration from the CA.");
                    else
                    {
                        var flag_san = 0x00040000; // EDITF_ATTRIBUTESUBJECTALTNAME2

                        if ((flags & flag_san) != flag_san)
                            Console.WriteLine("[*] The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is not set, toggling it on.");
                        else
                            Console.WriteLine("[*] The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is already set, toggling it off.");

                        flags ^= flag_san;

                        if (!CertAdmin.SetConfigEntry(server, authority, "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", flags))
                            Console.WriteLine("[X] Failed to set the EditFlags configuration on the CA.");
                        else
                            Console.WriteLine("[*] Successfully set the EditFlags configuration on the CA.");
                    }
                }

                if (opts.ToggleRpcEncryption)
                {
                    Console.WriteLine();
                    Console.WriteLine($"[*] Attempting to toggle IF_ENFORCEENCRYPTICERTREQUEST (ESC11) on the CA.");

                    if (!CertAdmin.GetConfigEntry(server, authority, null, "InterfaceFlags", out int flags))
                        Console.WriteLine("[X] Failed to retrieve the InterfaceFlags configuration from the CA.");
                    else
                    {
                        var flag_req = 0x00000200; // IF_ENFORCEENCRYPTICERTREQUEST

                        if ((flags & flag_req) != flag_req)
                            Console.WriteLine("[*] The IF_ENFORCEENCRYPTICERTREQUEST flag is not set, toggling it on.");
                        else
                            Console.WriteLine("[*] The IF_ENFORCEENCRYPTICERTREQUEST flag is already set, toggling it off.");
                            
                        flags ^= flag_req;

                        if (!CertAdmin.SetConfigEntry(server, authority, null, "InterfaceFlags", flags))
                            Console.WriteLine("[X] Failed to set the InterfaceFlags configuration on the CA.");
                        else
                            Console.WriteLine("[*] Successfully set the InterfaceFlags configuration on the CA.");
                    }
                }

                if (opts.ToggleNoExtension)
                {
                    Console.WriteLine();
                    Console.WriteLine($"[*] Attempting to toggle szOID_NTDS_CA_SECURITY_EXT in the DisableExtensionList attribute (ESC16) on the CA.");

                    if (!CertAdmin.GetConfigEntry(server, authority, "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList", out string[] extensions))
                        Console.WriteLine("[X] Failed to retrieve the DisableExtensionList configuration from the CA.");
                    else
                    {
                        var list = extensions.ToList();

                        if (!list.Contains(CommonOids.NtdsCaSecurityExt))
                        {
                            Console.WriteLine("[*] The szOID_NTDS_CA_SECURITY_EXT extension does not exist in DisableExtensionList, adding it.");
                            list.Add(CommonOids.NtdsCaSecurityExt);
                        }
                        else
                        {
                            Console.WriteLine("[*] The szOID_NTDS_CA_SECURITY_EXT extension already exists in DisableExtensionList, removing it.");
                            list.Remove(CommonOids.NtdsCaSecurityExt);
                        }

                        if (!CertAdmin.SetConfigEntry(server, authority, "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList", list.ToArray()))
                            Console.WriteLine("[X] Failed to set the DisableExtensionList configuration on the CA.");
                        else
                            Console.WriteLine("[*] Successfully set the DisableExtensionList configuration on the CA.");
                    }
                }

                RestartCaService(server);
            }
        }

        private static void RestartCaService(string server)
        {
            try
            {
                Console.WriteLine();
                Console.WriteLine($"[*] Attempting to restart the CA service.");

                using (var sc = new ServiceController("CertSvc", server))
                {
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped);
                        Console.WriteLine($"[*] Successfully stopped the CA service.");
                    }

                    sc.Start();
                    sc.WaitForStatus(ServiceControllerStatus.Running);
                    Console.WriteLine($"[*] Successfully restarted the CA service.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error restarting the CA service: {e.Message}");
            }
        }
    }
}

#endif