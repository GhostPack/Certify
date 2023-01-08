using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Web.Script.Serialization;
using Certify.Domain;
using Certify.Lib;
using static Certify.Lib.DisplayUtil;

namespace Certify.Commands
{
    class ResultDTO
    {
        // used for JSON serialization
        public Dictionary<string, object?> Meta { get; }
        public ResultDTO(string type, int count)
        {
            Meta = new Dictionary<string, object?>()
            {
                { "type", type },
                { "count", count },
                { "version", 3 }
            };
        }
    }

    class CAResultDTO : ResultDTO
    {
        // used for JSON serialization
        public List<EnterpriseCertificateAuthorityDTO> CertificateAuthorities { get; }
        public CAResultDTO(List<EnterpriseCertificateAuthorityDTO> certificateAuthorities)
            : base("certificateauthorities", certificateAuthorities.Count)
        {
            CertificateAuthorities = certificateAuthorities;
        }
    }

    class TemplateResultDTO : ResultDTO
    {
        // used for JSON serialization
        public List<CertificateTemplateDTO> CertificateTemplates { get; }
        public TemplateResultDTO(List<CertificateTemplateDTO> certificateTemplates)
            : base("certificatetemplates", certificateTemplates.Count)
        {
            CertificateTemplates = certificateTemplates;
        }
    }

    public enum FindFilter
    {
        None,
        Vulnerable,
        VulnerableCurrentUser,
        EnrolleeSuppliesSubject,
        ClientAuth
    }

    public class Find : ICommand
    {
        public static string CommandName => "find";
        private bool _hideAdmins;
        private bool _showAllPermissions;
        private bool _outputJSON;
        private string? _certificateAuthority = null;
        private string? _domain = null;
        private string? _ldapServer = null;
        private FindFilter _findFilter = FindFilter.None;

        public void Execute(Dictionary<string, string> arguments)
        {
            if (!arguments.ContainsKey("/json"))
                Console.WriteLine("[*] Action: Find certificate templates");

            if (arguments.ContainsKey("/domain"))
            {
                _domain = arguments["/domain"];
                if (!_domain.Contains("."))
                {
                    Console.WriteLine("[!] /domain:X must be a FQDN");
                    return;
                }
            }

            if (arguments.ContainsKey("/ldapserver"))
            {
                _ldapServer = arguments["/ldapserver"];
            }

            if (arguments.ContainsKey("/ca"))
            {
                _certificateAuthority = arguments["/ca"];
            }

            if (arguments.ContainsKey("/vulnerable"))
            {
                if (arguments.ContainsKey("/currentuser"))
                {
                    _findFilter = FindFilter.VulnerableCurrentUser;
                    Console.WriteLine("[*] Using current user's unrolled group SIDs for vulnerability checks.");
                }
                else
                {
                    _findFilter = FindFilter.Vulnerable;
                }
            }

            if (arguments.ContainsKey("/enrolleeSuppliesSubject"))
            {
                _findFilter = FindFilter.EnrolleeSuppliesSubject;
            }

            if (arguments.ContainsKey("/clientauth"))
            {
                _findFilter = FindFilter.ClientAuth;
            }

            if (arguments.ContainsKey("/json"))
            {
                _outputJSON = true;
            }

            _hideAdmins = arguments.ContainsKey("/hideAdmins");
            _showAllPermissions = arguments.ContainsKey("/showAllPermissions");


            FindTemplates(_outputJSON);
        }


        public void FindTemplates(bool outputJSON = false)
        {
            var ldap = new LdapOperations(new LdapSearchOptions()
            {
                Domain = _domain, LdapServer = _ldapServer
            });

            if (!outputJSON)
                Console.WriteLine($"[*] Using the search base '{ldap.ConfigurationPath}'");

            if (!string.IsNullOrEmpty(_certificateAuthority))
            {
                if (!outputJSON)
                    Console.WriteLine($"[*] Restricting to CA name : {_certificateAuthority}");
            }

            // get all of our current SIDs
            var ident = WindowsIdentity.GetCurrent();
            var currentUserSids = ident.Groups.Select(o => o.ToString()).ToList();
            currentUserSids.Add($"{ident.User}"); // make sure we get our current SID

            // enumerate information about every CA object
            var cas = ldap.GetEnterpriseCAs(_certificateAuthority);

            // used for JSON serialization
            var caDTOs = new List<EnterpriseCertificateAuthorityDTO>();

            if (!cas.Any())
            {
                Console.WriteLine(!outputJSON
                    ? "[!] There are no enterprise CAs and therefore no one can request certificates. Stopping..."
                    : "{\"Error\": \"There are no enterprise CAs and therefore no one can request certificates.\"}");

                return;
            }

            foreach (var ca in cas)
            {
                if (!outputJSON)
                {
                    Console.WriteLine($"\n[*] Listing info about the Enterprise CA '{ca.Name}'\n");
                    if (_findFilter == FindFilter.VulnerableCurrentUser)
                    {
                        PrintEnterpriseCaInfo(ca, _hideAdmins, _showAllPermissions, currentUserSids);
                    }
                    else
                    {
                        PrintEnterpriseCaInfo(ca, _hideAdmins, _showAllPermissions);
                    }
                }
                else
                {
                    // transform the CA object into a DTO
                    caDTOs.Add(new EnterpriseCertificateAuthorityDTO(ca));
                }
            }

            // enumerate information about all available templates
            var templates = ldap.GetCertificateTemplates();

            if (!outputJSON)
            {
                if (!templates.Any())
                {
                    Console.WriteLine("\n[!] No available templates found!\n");
                    return;
                }

                // display templates based on our search filter
                switch (_findFilter)
                {
                    case FindFilter.None:
                        ShowAllTemplates(templates, cas);
                        break;
                    case FindFilter.Vulnerable:
                        ShowVulnerableTemplates(templates, cas);
                        break;
                    case FindFilter.VulnerableCurrentUser:
                        ShowVulnerableTemplates(templates, cas, currentUserSids);
                        break;
                    case FindFilter.EnrolleeSuppliesSubject:
                        ShowTemplatesWithEnrolleeSuppliesSubject(templates, cas);
                        break;
                    case FindFilter.ClientAuth:
                        ShowTemplatesAllowingClientAuth(templates, cas);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException("_findFilter");
                }
            }
            else
            {
                var publishedTemplateNames = (
                    from t in templates
                    where t.Name != null && cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name))
                    select $"{t.Name}").Distinct().ToArray();

                var templateDTOs =
                    (from template in templates
                     where template.Name != null && publishedTemplateNames.Contains(template.Name)
                     select new CertificateTemplateDTO(template))
                    .ToList();

                // TODO: how to implement this in LINQ?

                var result = new List<object>()
                {
                    new CAResultDTO(caDTOs),
                    new TemplateResultDTO(templateDTOs)
                };

                var json = new JavaScriptSerializer();
                var jsonStr = json.Serialize(result);
                Console.WriteLine(jsonStr);
            }
        }


        private void PrintCertTemplate(EnterpriseCertificateAuthority ca, CertificateTemplate template)
        {
            Console.WriteLine($"    CA Name                               : {ca.FullName}");
            Console.WriteLine($"    Template Name                         : {template.Name}");
            Console.WriteLine($"    Schema Version                        : {template.SchemaVersion}");
            Console.WriteLine($"    Validity Period                       : {template.ValidityPeriod}");
            Console.WriteLine($"    Renewal Period                        : {template.RenewalPeriod}");
            Console.WriteLine($"    msPKI-Certificate-Name-Flag          : {template.CertificateNameFlag}");
            Console.WriteLine($"    mspki-enrollment-flag                 : {template.EnrollmentFlag}");
            Console.WriteLine($"    Authorized Signatures Required        : {template.AuthorizedSignatures}");
            if (template.RaApplicationPolicies != null && template.RaApplicationPolicies.Any())
            {
                var applicationPolicyFriendNames = template.RaApplicationPolicies
                    .Select(o => ((new Oid(o)).FriendlyName))
                    .OrderBy(s => s)
                    .ToArray();
                Console.WriteLine($"    Application Policies                  : {string.Join(", ", applicationPolicyFriendNames)}");
            }
            if (template.IssuancePolicies != null && template.IssuancePolicies.Any())
            {
                var issuancePolicyFriendNames = template.IssuancePolicies
                    .Select(o => ((new Oid(o)).FriendlyName))
                    .OrderBy(s => s)
                    .ToArray();
                Console.WriteLine($"    Issuance Policies                     : {string.Join(", ", issuancePolicyFriendNames)}");
            }

            var oidFriendlyNames = template.ExtendedKeyUsage == null
                ? new[] { "<null>" }
                : template.ExtendedKeyUsage.Select(o => ((new Oid(o)).FriendlyName))
                .OrderBy(s => s)
                .ToArray();
            Console.WriteLine($"    pkiextendedkeyusage                   : {string.Join(", ", oidFriendlyNames)}");

            var certificateApplicationPolicyFriendlyNames = template.ApplicationPolicies == null
                ? new[] { "<null>" }
                : template.ApplicationPolicies.Select(o => ((new Oid(o)).FriendlyName))
                .OrderBy(s => s)
                .ToArray();
            Console.WriteLine($"    mspki-certificate-application-policy  : {string.Join(", ", certificateApplicationPolicyFriendlyNames)}");

            Console.WriteLine("    Permissions");
            if (template.SecurityDescriptor == null)
            {
                Console.WriteLine("      Security descriptor is null");
            }
            else
            {
                if (_showAllPermissions)
                    PrintAllPermissions(template.SecurityDescriptor);
                else
                    PrintAllowPermissions(template.SecurityDescriptor);
            }

            Console.WriteLine();
        }

        private void PrintAllowPermissions(ActiveDirectorySecurity sd)
        {
            var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));
            var ownerName = $"{GetUserSidString(ownerSid.ToString())}";

            var enrollmentPrincipals = new List<string>();
            var allExtendedRightsPrincipals = new List<string>();
            var fullControlPrincipals = new List<string>();
            var writeOwnerPrincipals = new List<string>();
            var writeDaclPrincipals = new List<string>();
            var writePropertyPrincipals = new List<string>();

            var rules = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));
            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                if ($"{rule.AccessControlType}" != "Allow")
                    continue;

                var sid = rule.IdentityReference.ToString();
                if (_hideAdmins && IsAdminSid(sid))
                    continue;

                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                {
                    // 0e10c968-78fb-11d2-90d4-00c04f79dc55  ->  Certificates-Enrollment right
                    // a05b8cc2-17bc-4802-a710-e7c15ab866a2  ->  Certificates-AutoEnrollment right (not acutally used during enrollment)
                    // 00000000-0000-0000-0000-000000000000  ->  all extended rights
                    switch ($"{rule.ObjectType}")
                    {
                        case "0e10c968-78fb-11d2-90d4-00c04f79dc55":
                            enrollmentPrincipals.Add(GetUserSidString(sid));
                            break;
                        case "00000000-0000-0000-0000-000000000000":
                            allExtendedRightsPrincipals.Add(GetUserSidString(sid));
                            break;
                    }
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                {
                    fullControlPrincipals.Add(GetUserSidString(sid));
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                {
                    writeOwnerPrincipals.Add(GetUserSidString(sid));
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                {
                    writeDaclPrincipals.Add(GetUserSidString(sid));
                }
                if ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                {
                    writePropertyPrincipals.Add(GetUserSidString(sid));
                }
            }

            Console.WriteLine($"      Enrollment Permissions");


            if (enrollmentPrincipals.Count > 0)
            {
                var sbEP = new StringBuilder();
                enrollmentPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbEP.Append($"{p}\n                                      "); });
                Console.WriteLine($"        Enrollment Rights           : {sbEP.ToString().Trim()}");
            }

            if (allExtendedRightsPrincipals.Count > 0)
            {
                var sbAER = new StringBuilder();
                allExtendedRightsPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbAER.Append($"{p}\n                                      "); });
                Console.WriteLine($"        All Extended Rights         : {sbAER.ToString().Trim()}");
            }

            Console.WriteLine("      Object Control Permissions");

            if (!(_hideAdmins && IsAdminSid(ownerSid.ToString())))
                Console.WriteLine($"        Owner                       : {ownerName}");

            if (fullControlPrincipals.Count > 0)
            {
                var sbGA = new StringBuilder();
                fullControlPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbGA.Append($"{p}\n                                      "); });
                Console.WriteLine($"        Full Control Principals     : {sbGA.ToString().Trim()}");
            }

            if (writeOwnerPrincipals.Count > 0)
            {
                var sbWO = new StringBuilder();
                writeOwnerPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbWO.Append($"{p}\n                                      "); });
                Console.WriteLine($"        WriteOwner Principals       : {sbWO.ToString().Trim()}");
            }

            if (writeDaclPrincipals.Count > 0)
            {
                var sbWD = new StringBuilder();
                writeDaclPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbWD.Append($"{p}\n                                      "); });
                Console.WriteLine($"        WriteDacl Principals        : {sbWD.ToString().Trim()}");
            }

            if (writePropertyPrincipals.Count > 0)
            {
                var sbWP = new StringBuilder();
                writePropertyPrincipals
                    .OrderBy(p => p)
                    .ToList()
                    .ForEach(p => { sbWP.Append($"{p}\n                                      "); });
                Console.WriteLine($"        WriteProperty Principals    : {sbWP.ToString().Trim()}");
            }
        }

        private void PrintAllPermissions(ActiveDirectorySecurity sd)
        {
            var ownerSid = sd.GetOwner(typeof(SecurityIdentifier));
            var ownerStr = GetUserSidString(ownerSid.ToString());
            var aces = sd.GetAccessRules(true, true, typeof(SecurityIdentifier));


            Console.WriteLine($"\n      Owner: {ownerStr}\n");
            Console.WriteLine(
                "      AccessControlType|PrincipalSid|PrincipalName|ActiveDirectoryRights|ObjectType|ObjectFlags|InheritanceType|InheritedObjectType|InheritanceFlags|IsInherited|PropagationFlags");

            foreach (ActiveDirectoryAccessRule ace in aces)
            {
                var objectTypeString = ConvertGuidToName(ace.ObjectType.ToString()) ?? ace.ObjectType.ToString();
                var inheritedObjectTypeString = ConvertGuidToName(ace.InheritedObjectType.ToString()) ?? ace.InheritedObjectType.ToString();
                var principalName = ConvertSidToName(ace.IdentityReference.Value);

                Console.WriteLine(
                    $"      {ace.AccessControlType}|{ace.IdentityReference}|{principalName}|{ace.ActiveDirectoryRights}|{objectTypeString}|{ace.ObjectFlags}|{ace.InheritanceType}|{inheritedObjectTypeString}|{ace.InheritanceFlags}|{ace.IsInherited}|{ace.PropagationFlags}");
            }
        }

        private string? ConvertGuidToName(string guid)
        {
            return guid switch
            {
                "0e10c968-78fb-11d2-90d4-00c04f79dc55" => "Enrollment",
                "a05b8cc2-17bc-4802-a710-e7c15ab866a2" => "AutoEnrollment",
                "00000000-0000-0000-0000-000000000000" => "All",
                _ => null
            };
        }

        private string? ConvertSidToName(string sid)
        {
            try
            {
                var sidObj = new SecurityIdentifier(sid);
                return sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return null;
        }


        private void ShowTemplatesWithEnrolleeSuppliesSubject(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas)
        {
            Console.WriteLine("Enabled certificate templates where users can supply a SAN:");

            foreach (var template in templates)
            {
                if (template.Name == null)
                {
                    Console.WriteLine("   Warning: Found a template, but could not get its name. Ignoring it.");
                    continue;
                }

                foreach (var ca in cas)
                {
                    if (ca.Templates != null && !ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    if (template.CertificateNameFlag != null && !((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT))
                        continue;

                    PrintCertTemplate(ca, template);
                }
            }
        }

        private void ShowTemplatesAllowingClientAuth(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas)
        {
            Console.WriteLine("Enabled certificate templates capable of client authentication:");

            foreach (var template in templates)
            {
                if (template.Name == null)
                {
                    Console.WriteLine($"   Warning: Unable to get the name of the template '{template.DistinguishedName}'. Ignoring it.");
                    continue;
                }

                foreach (var ca in cas)
                {
                    if (ca.Templates != null && !ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    var hasAuthenticationEku =
                        template.ExtendedKeyUsage != null &&
                        (template.ExtendedKeyUsage.Contains(CommonOids.SmartcardLogon) ||
                        template.ExtendedKeyUsage.Contains(CommonOids.ClientAuthentication) ||
                        template.ExtendedKeyUsage.Contains(CommonOids.PKINITClientAuthentication));

                    if (hasAuthenticationEku)
                        PrintCertTemplate(ca, template);
                }
            }
        }

        private void ShowAllTemplates(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas)
        {
            Console.WriteLine("\n[*] Available Certificates Templates :\n");

            foreach (var template in templates)
            {
                if (template.Name == null)
                {
                    Console.WriteLine($"   Warning: Unable to get the name of the template '{template.DistinguishedName}'. Ignoring it.");
                    continue;
                }

                foreach (var ca in cas)
                {
                    if (ca.Templates != null && !ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    PrintCertTemplate(ca, template);
                }
            }
        }

        private void ShowVulnerableTemplates(IEnumerable<CertificateTemplate> templates, IEnumerable<EnterpriseCertificateAuthority> cas, List<string>? currentUserSids = null)
        {
            foreach (var t in templates.Where(t => t.Name == null))
            {
                Console.WriteLine($"[!] Warning: Could not get the name of the template {t.DistinguishedName}. Analysis will be incomplete as a result.");
            }

            var unusedTemplates = (
                from t in templates
                where t.Name != null && !cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name)) && IsCertificateTemplateVulnerable(t)
                select $"{t.Name}").ToArray();

            var vulnerableTemplates = (
                from t in templates
                where t.Name != null && cas.Any(ca => ca.Templates != null && ca.Templates.Contains(t.Name)) && IsCertificateTemplateVulnerable(t)
                select $"{t.Name}").ToArray();

            if (unusedTemplates.Any())
            {
                Console.WriteLine("\n[!] Vulnerable certificate templates that exist but an Enterprise CA does not publish:\n");
                Console.WriteLine($"    {string.Join("\n    ", unusedTemplates)}\n");
            }

            Console.WriteLine(!vulnerableTemplates.Any()
                ? "\n[+] No Vulnerable Certificates Templates found!\n"
                : "\n[!] Vulnerable Certificates Templates :\n");

            foreach (var template in templates)
            {
                if (!IsCertificateTemplateVulnerable(template, currentUserSids))
                    continue;

                foreach (var ca in cas)
                {
                    if (ca.Templates == null)
                    {
                        Console.WriteLine($"   Warning: Unable to get the published templates on the CA {ca.DistinguishedName}. Ignoring it...");
                        continue;
                    }
                    if (template.Name == null)
                    {
                        Console.WriteLine($"   Warning: Unable to get the name of the template {template.DistinguishedName}. Ignoring it...");
                        continue;
                    }

                    if (!ca.Templates.Contains(template.Name)) // check if this CA has this template enabled
                        continue;

                    PrintCertTemplate(ca, template);
                }
            }
        }

        private bool IsCertificateTemplateVulnerable(CertificateTemplate template, List<string>? currentUserSids = null)
        {
            if (template.SecurityDescriptor == null)
                throw new NullReferenceException($"Could not get the security descriptor for the template '{template.DistinguishedName}'");

            var ownerSID = $"{template.SecurityDescriptor.GetOwner(typeof(SecurityIdentifier)).Value}";

            if (currentUserSids == null)
            {
                // Check 1) is the owner a low-privileged user?
                if (IsLowPrivSid(ownerSID))
                {
                    return true;
                }
            }
            else
            {
                // Check 1) is the owner is a principal we're nested into
                if (currentUserSids.Contains(ownerSID))
                {
                    return true;
                }
            }

            // Check misc) Can low privileged users/the current user enroll?
            var lowPrivilegedUsersCanEnroll = false;

            // Check 2) do low-privileged users/the current user have edit rights over the template?
            var vulnerableACL = false;
            foreach (ActiveDirectoryAccessRule rule in template.SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (currentUserSids == null)
                {
                    // check for low-privileged control relationships
                    if (
                        ($"{rule.AccessControlType}" == "Allow")
                        && (IsLowPrivSid(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                        )
                    )
                    {
                        vulnerableACL = true;
                    }
                    // check for low-privileged enrollment
                    else if (
                        ($"{rule.AccessControlType}" == "Allow")
                        && (IsLowPrivSid(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                            && (
                                $"{rule.ObjectType}" == "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                                || $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000"
                            )
                        )
                    )
                    {
                        lowPrivilegedUsersCanEnroll = true;
                    }
                }
                else
                {
                    // check for current-user control relationships
                    if (
                        ($"{rule.AccessControlType}" == "Allow")
                        && (currentUserSids.Contains(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.GenericAll) == ActiveDirectoryRights.GenericAll)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteOwner) == ActiveDirectoryRights.WriteOwner)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteDacl) == ActiveDirectoryRights.WriteDacl)
                            || ((rule.ActiveDirectoryRights & ActiveDirectoryRights.WriteProperty) == ActiveDirectoryRights.WriteProperty && $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                        )
                    )
                    {
                        vulnerableACL = true;
                    }

                    // check for current-user enrollment
                    if (
                        ($"{rule.AccessControlType}" == "Allow")
                        && (currentUserSids.Contains(rule.IdentityReference.Value.ToString()))
                        && (
                            ((rule.ActiveDirectoryRights & ActiveDirectoryRights.ExtendedRight) == ActiveDirectoryRights.ExtendedRight)
                            && (
                                $"{rule.ObjectType}" == "0e10c968-78fb-11d2-90d4-00c04f79dc55"
                                || $"{rule.ObjectType}" == "00000000-0000-0000-0000-000000000000"
                            )
                        )
                    )
                    {
                        lowPrivilegedUsersCanEnroll = true;
                    }
                }

            }

            if (vulnerableACL)
            {
                return true;
            }


            // Check 3) Is manager approval enabled?
            var requiresManagerApproval = template.EnrollmentFlag != null && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
            if (requiresManagerApproval) return false;

            // Check 4) Are there now authorized signatures required?
            if (template.AuthorizedSignatures > 0) return false;


            // Check 5) If a low priv'ed user can request a cert with EKUs used for authentication and ENROLLEE_SUPPLIES_SUBJECT is enabled, then privilege escalation is possible
            var enrolleeSuppliesSubject = template.CertificateNameFlag != null && ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);
            var hasAuthenticationEku =
                template.ExtendedKeyUsage != null &&
                (template.ExtendedKeyUsage.Contains(CommonOids.SmartcardLogon) ||
                template.ExtendedKeyUsage.Contains(CommonOids.ClientAuthentication) ||
                template.ExtendedKeyUsage.Contains(CommonOids.PKINITClientAuthentication));

            if (lowPrivilegedUsersCanEnroll && enrolleeSuppliesSubject && hasAuthenticationEku) return true;


            // Check 6) If a low priv'ed user can request a cert with any of these EKUs (or no EKU), then privilege escalation is possible
            var hasDangerousEku =
                template.ExtendedKeyUsage == null
                || !template.ExtendedKeyUsage.Any() // No EKUs == Any Purpose
                || template.ExtendedKeyUsage.Contains(CommonOids.AnyPurpose)
                || template.ExtendedKeyUsage.Contains(CommonOids.CertificateRequestAgent)
                || (template.ApplicationPolicies != null && template.ApplicationPolicies.Contains(CommonOids.CertificateRequestAgentPolicy));

            if (lowPrivilegedUsersCanEnroll && hasDangerousEku) return true;


            // Check 7) Does a certificate contain the  DISABLE_EMBED_SID_OID flag + DNS and DNS SAN flags
            if ( template.CertificateNameFlag==null || template.EnrollmentFlag == null) {
                return false;
            }
            
            if((((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS)
                || ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.SUBJECT_REQUIRE_DNS_AS_CN))
                && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.NO_SECURITY_EXTENSION)) {
                return true;
            }

            return false;
        }
    }
}
