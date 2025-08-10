using System;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Certify.Domain;

namespace Certify.Lib
{
    class DisplayUtil
    {
        public static void PrintPkiObjectControllers(Dictionary<string, List<Tuple<string, string>>> object_controllers, bool hide_admins)
        {
            foreach (var object_controller in object_controllers.OrderBy(o => GetUserNameFromSid(o.Key)))
            {
                if (object_controller.Value.Count != 0)
                {
                    var user_sid = object_controller.Key;
                    var user_name = GetUserNameFromSid(user_sid);

                    if (!hide_admins || (!SidUtil.IsAdminSid(user_sid) && user_sid != "S-1-5-18"))
                    {
                        Console.WriteLine();

                        if (string.IsNullOrEmpty(user_name))
                            Console.WriteLine($"    {user_sid}");
                        else
                            Console.WriteLine($"    {user_name} ({user_sid})");

                        foreach (var entry in object_controller.Value)
                            Console.WriteLine($"        {entry.Item1,-18} {entry.Item2}");
                    }
                }
            }
        }

        public static void PrintEnterpriseCaInfo(CertificateAuthorityEnterprise ca, bool hide_admins, bool show_all_permissions)
        {
            if (ca == null)
                throw new NullReferenceException("CA is null");

            Console.WriteLine($"    Enterprise CA Name            : {ca.Name}");
            Console.WriteLine($"    DNS Hostname                  : {ca.DnsHostname}");
            Console.WriteLine($"    FullName                      : {ca.FullName}");
            Console.WriteLine($"    Flags                         : {ca.Flags}");

            foreach (var certificate in ca.Certificates)
                PrintCertificateInfo(certificate);

            Console.WriteLine($"    User Specifies SAN            : {ca.UserSpecifiedSan}");
            Console.WriteLine($"    RPC Request Encryption        : {ca.RpcRequestEncryption}");

            if (ca.RpcRequestRestrictions.Any())
                Console.WriteLine($"    RPC Request Restrictions      : {string.Join(", ", ca.RpcRequestRestrictions)}");
            
            if (ca.DisabledExtensions.Any())
            {
                var disabled_extensions = ca.DisabledExtensions
                     .Select(o => $"{(new Oid(o)).FriendlyName ?? "<unknown>"} ({o})")
                     .OrderBy(s => s)
                     .ToArray();

                var join_sep = "\n                                    ";
                Console.WriteLine($"    Disabled Extensions           : {string.Join(join_sep, disabled_extensions)}");
            }

            if (ca.Vulnerabilities != null && ca.Vulnerabilities.Any())
            {
                Console.WriteLine($"    Vulnerabilities");

                foreach (var v in ca.Vulnerabilities.OrderBy(v => v.Key))
                    Console.WriteLine($"      {"ESC" + v.Key,-27} : {v.Value}");
            }

            Console.WriteLine("    CA Permissions");

            var security_descriptor = ca.GetServerSecurityFromRegistry();

            if (security_descriptor != null)
            { 
                var owner_sid = security_descriptor.GetOwner(typeof(SecurityIdentifier));
                var owner_str = GetUserSidString(owner_sid.ToString());
            
                Console.WriteLine($"      Owner: {owner_str}");
                Console.WriteLine();

                if (!show_all_permissions)
                    Console.WriteLine($"      {"Access",-6} {"Rights",-42} Principal");

                foreach (ActiveDirectoryAccessRule rule in security_descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var sid = rule.IdentityReference.ToString();
                    var rights = (CertificationAuthorityRights)rule.ActiveDirectoryRights;

                    if (!hide_admins || !SidUtil.IsAdminSid(sid))
                    {
                        if (!show_all_permissions)
                            Console.WriteLine($"      {rule.AccessControlType,-6} {rights,-42} {GetUserSidString(sid)}");
                        else
                        {
                            Console.WriteLine($"      Identity                    : {GetUserSidString(sid)}");
                            Console.WriteLine($"        AccessControlType         : {rule.AccessControlType}");
                            Console.WriteLine($"        Rights                    : {rights}");
                            Console.WriteLine($"        ObjectType                : {rule.ObjectType}");
                            Console.WriteLine($"        IsInherited               : {rule.IsInherited}");
                            Console.WriteLine($"        InheritedObjectType       : {rule.InheritedObjectType}");
                            Console.WriteLine($"        InheritanceFlags          : {rule.InheritanceFlags}");
                            Console.WriteLine($"        PropagationFlags          : {rule.PropagationFlags}");
                            Console.WriteLine();
                        }
                    }
                }

                // bit more complicated than anticipated, as template names can be emebedded in the DACL
                // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/b497b1e1-a84c-40c8-9379-524193176fad

                var ea_security_descriptor = ca.GetEnrollmentAgentSecurity();

                if (ea_security_descriptor == null)
                    Console.WriteLine("    Enrollment Agent Restrictions : None");
                else
                {
                    Console.WriteLine("    Enrollment Agent Restrictions :");

                    foreach (CommonAce ace in ea_security_descriptor.DiscretionaryAcl)
                    {
                        var entry = new EnrollmentAgentRestriction(ace);
                        Console.WriteLine($"      {GetUserSidString(entry.Agent)}");
                        Console.WriteLine($"        Template : {entry.Template}");
                        Console.WriteLine($"        Targets  :");

                        foreach (var target in entry.Targets)
                            Console.WriteLine($"          {GetUserSidString(target, 31)}");
                    }
                }

                Console.WriteLine();
            }
        }

        public static void PrintCertificateInfo(X509Certificate2 certificate)
        {
            Console.WriteLine($"    Cert SubjectName              : {certificate.SubjectName.Name}");
            Console.WriteLine($"    Cert Thumbprint               : {certificate.Thumbprint}");
            Console.WriteLine($"    Cert Serial                   : {certificate.SerialNumber}");
            Console.WriteLine($"    Cert Start Date               : {certificate.NotBefore}");
            Console.WriteLine($"    Cert End Date                 : {certificate.NotAfter}");

            var chain = new X509Chain();
            chain.Build(certificate);

            var names = new List<string>();

            foreach (var element in chain.ChainElements)
                names.Insert(0, element.Certificate.SubjectName.Name.Replace(" ", ""));

            Console.WriteLine($"    Cert Chain                    : {string.Join(" -> ", names)}");
        }

        public static void PrintCertificateTemplateInfo(IEnumerable<CertificateAuthorityEnterprise> cas, CertificateTemplate template, bool hide_admins, bool show_all_permissions)
        {
            Console.WriteLine();
            Console.WriteLine($"    Template Name                         : {template.Name}");
            Console.WriteLine($"    Enabled                               : {cas.Any()}");

            if (cas.Any())
            {
                var join_sep = "\n                                            ";
                Console.WriteLine($"    Publishing CAs                        : {string.Join(join_sep, cas.Select(ca => ca.FullName))}");
            }

            Console.WriteLine($"    Schema Version                        : {template.SchemaVersion}");
            Console.WriteLine($"    Validity Period                       : {template.ValidityPeriod}");
            Console.WriteLine($"    Renewal Period                        : {template.RenewalPeriod}");
            Console.WriteLine($"    Certificate Name Flag                 : {template.CertificateNameFlag}");
            Console.WriteLine($"    Enrollment Flag                       : {template.EnrollmentFlag}");
            Console.WriteLine($"    Manager Approval Required             : {template.ManagerApproval}");
            Console.WriteLine($"    Authorized Signatures Required        : {template.AuthorizedSignatures}");

            if (template.RaApplicationPolicies != null && template.RaApplicationPolicies.Any())
            {
                var application_policy_friendly_names = template.RaApplicationPolicies
                    .Select(o => (new Oid(o)).FriendlyName)
                    .OrderBy(s => s)
                    .ToArray();

                Console.WriteLine($"    Required Application Policies         : {string.Join(", ", application_policy_friendly_names)}");
            }

            if (template.RaIssuancePolicies != null && template.RaIssuancePolicies.Any())
            {
                var issuance_policy_friendly_names = template.RaIssuancePolicies
                    .Select(o => (new Oid(o)).FriendlyName)
                    .OrderBy(s => s)
                    .ToArray();

                Console.WriteLine($"    Required Issuance Policies            : {string.Join(", ", issuance_policy_friendly_names)}");
            }

            if (template.ExtendedKeyUsage == null)
                Console.WriteLine("    Extended Key Usage                    : <null>");
            else
            {
                var extended_key_usage_friendly_names = template.ExtendedKeyUsage
                    .Select(o => (new Oid(o)).FriendlyName)
                    .OrderBy(s => s)
                    .ToArray();

                Console.WriteLine($"    Extended Key Usage                    : {string.Join(", ", extended_key_usage_friendly_names)}");
            }

            if (template.ApplicationPolicies == null)
                Console.WriteLine("    Certificate Application Policies      : <null>");
            else
            {
                var certificate_application_policy_friendly_names = template.ApplicationPolicies
                    .Select(o => (new Oid(o)).FriendlyName)
                    .OrderBy(s => s)
                    .ToArray();

                Console.WriteLine($"    Certificate Application Policies      : {string.Join(", ", certificate_application_policy_friendly_names)}");
            }

            if (template.IssuancePolicies != null && template.IssuancePolicies.Any())
            {
                var certificate_issuance_policy_friendly_names = template.IssuancePolicies
                    .Select(o => $"{o.DisplayName} (" + (o.GroupLink != null ? $"linked to group '{o.GroupLink}'" : "no linked groups") + ")")
                    .OrderBy(s => s)
                    .ToArray();

                var join_sep = "\n                                            ";
                Console.WriteLine($"    Certificate Issuance Policies         : {string.Join(join_sep, certificate_issuance_policy_friendly_names)}");
            }

            if (template.Vulnerabilities != null && template.Vulnerabilities.Any())
            {
                Console.WriteLine($"    Vulnerabilities");

                foreach (var v in template.Vulnerabilities.OrderBy(v => v.Key))
                    Console.WriteLine($"      {"ESC"+v.Key,-35} : {v.Value}");
            }

            Console.WriteLine("    Permissions");

            if (template.SecurityDescriptor == null)
                Console.WriteLine("      Security descriptor is null");
            else if (show_all_permissions)
                PrintAllPermissions(template.SecurityDescriptor);
            else
                PrintAllowPermissions(template.SecurityDescriptor, hide_admins);
        }

        private static void PrintAllPermissions(ActiveDirectorySecurity sd)
        {
            var owner_sid = sd.GetOwner(typeof(SecurityIdentifier));
            var owner_str = GetUserSidString(owner_sid.ToString());

            Console.WriteLine();
            Console.WriteLine($"      Owner: {owner_str}");
            Console.WriteLine();
            Console.WriteLine("      AccessControlType|PrincipalSid|PrincipalName|ActiveDirectoryRights|ObjectType|ObjectFlags|InheritanceType|InheritedObjectType|InheritanceFlags|IsInherited|PropagationFlags");

            foreach (ActiveDirectoryAccessRule ace in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                var object_type_str = GetAccessControlTypeFromGuid(ace.ObjectType.ToString()) ?? ace.ObjectType.ToString();
                var inherited_object_type_str = GetAccessControlTypeFromGuid(ace.InheritedObjectType.ToString()) ?? ace.InheritedObjectType.ToString();
                var principal_name = GetUserNameFromSid(ace.IdentityReference.Value);

                Console.WriteLine($"      {ace.AccessControlType}|{ace.IdentityReference}|{principal_name}|{ace.ActiveDirectoryRights}|{object_type_str}|{ace.ObjectFlags}|{ace.InheritanceType}|{inherited_object_type_str}|{ace.InheritanceFlags}|{ace.IsInherited}|{ace.PropagationFlags}");
            }
        }

        private static void PrintAllowPermissions(ActiveDirectorySecurity sd, bool hide_admins)
        {
            var enrollment_principals = new List<string>();
            var all_extended_rights_principals = new List<string>();
            var full_control_principals = new List<string>();
            var write_owner_principals = new List<string>();
            var write_dacl_principals = new List<string>();
            var write_property_principals = new List<string>();

            foreach (ActiveDirectoryAccessRule ace in sd.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                var sid = ace.IdentityReference.ToString();

                if (ace.AccessControlType == AccessControlType.Allow && (!hide_admins || !SidUtil.IsAdminSid(sid)))
                {
                    if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.ExtendedRight))
                    {
                        switch ($"{ace.ObjectType}")
                        {
                            case "0e10c968-78fb-11d2-90d4-00c04f79dc55": // Certificate enrollment rights
                                enrollment_principals.Add(GetUserSidString(sid));
                                break;

                            case "a05b8cc2-17bc-4802-a710-e7c15ab866a2": // Certificate auto-enrollment rights (not actually used during enrollment)
                                break;

                            case "00000000-0000-0000-0000-000000000000": // All extended rights
                                all_extended_rights_principals.Add(GetUserSidString(sid));
                                break;
                        }
                    }

                    if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll))
                        full_control_principals.Add(GetUserSidString(sid));

                    if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                        write_owner_principals.Add(GetUserSidString(sid));

                    if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                        write_dacl_principals.Add(GetUserSidString(sid));

                    if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteProperty) && $"{ace.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                        write_property_principals.Add(GetUserSidString(sid)); // WriteAllProperties?
                }
            }

            var join_sep =  "\n                                      ";

            Console.WriteLine("      Enrollment Permissions");

            if (enrollment_principals.Any())
                Console.WriteLine($"        Enrollment Rights           : {string.Join(join_sep, enrollment_principals.OrderBy(p => p).ToList())}");

            if (all_extended_rights_principals.Any())
                Console.WriteLine($"        All Extended Rights         : {string.Join(join_sep, all_extended_rights_principals.OrderBy(p => p).ToList())}");

            Console.WriteLine("      Object Control Permissions");

            var owner_sid = sd.GetOwner(typeof(SecurityIdentifier));

            if (!hide_admins || !SidUtil.IsAdminSid(owner_sid.ToString()))
                Console.WriteLine($"        Owner                       : {GetUserSidString(owner_sid.ToString())}");

            if (full_control_principals.Any())
                Console.WriteLine($"        Full Control                : {string.Join(join_sep, full_control_principals.OrderBy(p => p).ToList())}");

            if (write_owner_principals.Any())
                Console.WriteLine($"        Write Owner                 : {string.Join(join_sep, write_owner_principals.OrderBy(p => p).ToList())}");

            if (write_dacl_principals.Any())
                Console.WriteLine($"        Write Dacl                  : {string.Join(join_sep, write_dacl_principals.OrderBy(p => p).ToList())}");

            if (write_property_principals.Any())
                Console.WriteLine($"        Write Property              : {string.Join(join_sep, write_property_principals.OrderBy(p => p).ToList())}");
        }

        private static string GetAccessControlTypeFromGuid(string guid)
        {
            return guid switch
            {
                "0e10c968-78fb-11d2-90d4-00c04f79dc55" => "Enrollment",
                "a05b8cc2-17bc-4802-a710-e7c15ab866a2" => "AutoEnrollment",
                "00000000-0000-0000-0000-000000000000" => "All",
                _ => null
            };
        }

        public static string GetUserSidString(string sid, int padding = 35)
        {
            return GetUserNameFromSid(sid).PadRight(padding) + sid;
        }

        public static string GetUserNameFromSid(string sid)
        {
            try
            {
                var sid_object = new SecurityIdentifier(sid);
                return sid_object.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
                return "<UNKNOWN>";
            }
        }
    }
}
