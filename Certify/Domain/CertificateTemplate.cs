using Certify.Lib;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Certify.Domain
{
    // from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
    // and from certutil.exe -v -dstemplate
    [Flags]
    public enum msPKICertificateNameFlag : uint
    {
        NONE = 0x00000000,
        ENROLLEE_SUPPLIES_SUBJECT = 0x00000001,
        ADD_EMAIL = 0x00000002,
        ADD_OBJ_GUID = 0x00000004,
        OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008,
        ADD_DIRECTORY_PATH = 0x00000100,
        ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000,
        SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000,
        SUBJECT_ALT_REQUIRE_SPN = 0x00800000,
        SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000,
        SUBJECT_ALT_REQUIRE_UPN = 0x02000000,
        SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000,
        SUBJECT_ALT_REQUIRE_DNS = 0x08000000,
        SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000,
        SUBJECT_REQUIRE_EMAIL = 0x20000000,
        SUBJECT_REQUIRE_COMMON_NAME = 0x40000000,
        SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000,
    }

    // from https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
    // and from certutil.exe -v -dstemplate
    [Flags]
    public enum msPKIEnrollmentFlag : uint
    {
        NONE = 0x00000000,
        INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001,
        PEND_ALL_REQUESTS = 0x00000002,
        PUBLISH_TO_KRA_CONTAINER = 0x00000004,
        PUBLISH_TO_DS = 0x00000008,
        AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010,
        AUTO_ENROLLMENT = 0x00000020,
        PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040,
        DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x00000080,
        USER_INTERACTION_REQUIRED = 0x00000100,
        ADD_TEMPLATE_NAME = 0x00000200,
        REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400,
        ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800,
        ADD_OCSP_NOCHECK = 0x00001000,
        ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000,
        NOREVOCATIONINFOINISSUEDCERTS = 0x00004000,
        INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000,
        ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000,
        ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000,
        SKIP_AUTO_RENEWAL = 0x00040000,
        NO_SECURITY_EXTENSION = 0x00080000
    }

    class CertificateTemplateACE
    {
        public string Type { get; }
        public string Rights { get; }
        public Guid ObjectType { get; }
        public string Principal { get; }

        public CertificateTemplateACE(AccessControlType access_type, ActiveDirectoryRights rights, Guid object_type, string principal)
        {
            Type = access_type.ToString();
            Rights = rights.ToString();
            ObjectType = object_type;
            Principal = principal;
        }
    }

    class CertificateTemplateACL
    {
        public string Owner { get; }
        public List<CertificateTemplateACE> ACEs { get; } = new List<CertificateTemplateACE>();

        public CertificateTemplateACL(ActiveDirectorySecurity security_descriptor)
        {
            Owner = ((SecurityIdentifier)security_descriptor.GetOwner(typeof(SecurityIdentifier))).Value.ToString();

            foreach (ActiveDirectoryAccessRule rule in security_descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                ACEs.Add(new CertificateTemplateACE(rule.AccessControlType, rule.ActiveDirectoryRights, rule.ObjectType, 
                    ((SecurityIdentifier)rule.IdentityReference).Value.ToString()));
            }
        }
    }

    class CertificateEnterpriseOid : ADObject
    {
        public Guid Guid { get; }
        public string Name { get; }
        public string DisplayName { get; }
        public Oid Oid { get; }
        public string GroupLink { get; }

        public CertificateEnterpriseOid(string dn, string name, Guid guid, string display_name, Oid oid, string group_link, ActiveDirectorySecurity security_descriptor)
            : base(dn, security_descriptor)
        {
            Name = name;
            Guid = guid;
            DisplayName = display_name;
            Oid = oid;
            GroupLink = group_link;
        }
    }

    class CertificateTemplate : ADObject
    {
        public string Name { get; }
        public string DomainName { get; }
        public Guid Guid { get; }
        public int SchemaVersion { get; }
        public string DisplayName { get; }
        public string ValidityPeriod { get; }
        public string RenewalPeriod { get; }
        public Oid Oid { get; }
        public msPKICertificateNameFlag CertificateNameFlag { get; }
        public msPKIEnrollmentFlag EnrollmentFlag { get; }
        public IEnumerable<string> ExtendedKeyUsage { get; }
        public bool ManagerApproval { get; }
        public int AuthorizedSignatures { get; }
        public IEnumerable<string> RaApplicationPolicies { get; }
        public IEnumerable<string> RaIssuancePolicies { get; }
        public IEnumerable<string> ApplicationPolicies { get; }
        public IEnumerable<CertificateEnterpriseOid> IssuancePolicies { get; }

        public Dictionary<int, string> Vulnerabilities { get; } = new Dictionary<int, string>();

        public CertificateTemplate(string dn, string name, string domain, Guid guid, int schema_version, string display_name, string validity_period,
            string renewal_period, Oid oid, msPKICertificateNameFlag certificate_name_flag, msPKIEnrollmentFlag enrollment_flag, IEnumerable<string> extended_key_usage,
            int authorized_signatures, IEnumerable<string> ra_application_policies, IEnumerable<string> ra_issuance_policies, ActiveDirectorySecurity security_descriptor,
            IEnumerable<string> application_policies, IEnumerable<CertificateEnterpriseOid> issuance_policies, List<string> user_sids) : base(dn, security_descriptor)
        {
            Name = name;
            DomainName = domain;
            Guid = guid;
            SchemaVersion = schema_version;
            DisplayName = display_name;
            ValidityPeriod = validity_period;
            RenewalPeriod = renewal_period;
            Oid = oid;
            CertificateNameFlag = certificate_name_flag;
            EnrollmentFlag = enrollment_flag;
            ExtendedKeyUsage = extended_key_usage;
            ManagerApproval = EnrollmentFlag.HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
            AuthorizedSignatures = authorized_signatures;
            RaApplicationPolicies = ra_application_policies;
            RaIssuancePolicies = ra_issuance_policies;
            ApplicationPolicies = application_policies;
            IssuancePolicies = issuance_policies;

            FindVulnerabilities(user_sids);
        }

        private void FindVulnerabilities(List<string> user_sids)
        {
            CheckVulnerableEsc4(user_sids, out bool has_enroll_rights);

            // Is manager approval disabled and are no authorized signatures required?
            if (!ManagerApproval && AuthorizedSignatures == 0)
            {
                if (has_enroll_rights)
                {
                    CheckVulnerableEsc1();
                    CheckVulnerableEsc2();
                    CheckVulnerableEsc3();
                    CheckVulnerableEsc9();
                    CheckVulnerableEsc13();
                    CheckVulnerableEsc15();
                }
            }
        }

        private void CheckVulnerableEsc1()
        {
            var auth_oids = new List<string>()
            {
                CommonOids.ClientAuthentication,
                CommonOids.PKINITClientAuthentication,
                CommonOids.SmartcardLogon,
                CommonOids.AnyPurpose,
            };

            if ((ExtendedKeyUsage == null || !ExtendedKeyUsage.Any() || ExtendedKeyUsage.Any(o => auth_oids.Contains(o))) &&
                CertificateNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT))
            {
                Vulnerabilities.Add(1, "The template has a client authentication EKU and allows enrollees to supply subject.");
            }
        }

        private void CheckVulnerableEsc2()
        {
            if (!CertificateNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT))
            {
                if (ExtendedKeyUsage == null || !ExtendedKeyUsage.Any())
                    Vulnerabilities.Add(2, "The template has no EKUs (Subordinate CA).");
                else if (ExtendedKeyUsage.Contains(CommonOids.AnyPurpose))
                    Vulnerabilities.Add(2, "The template has the 'Any Purpose' EKU.");
            }
        }

        private void CheckVulnerableEsc3()
        {
            if (ExtendedKeyUsage != null && ExtendedKeyUsage.Contains(CommonOids.CertificateRequestAgent))
            {
                // According to blog post : https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d
                // If a template contains the "AnyPurpose" EKU as well, the certificate cannot be used to enroll on behalf of other users in schema version 2+ templates
                if (ExtendedKeyUsage.Contains(CommonOids.AnyPurpose))
                    Vulnerabilities.Add(3, "The template has the 'Certificate Request Agent' EKU, but only works for schema version 1 templates.");
                else
                    Vulnerabilities.Add(3, "The template has the 'Certificate Request Agent' EKU.");
            }
        }

        private void CheckVulnerableEsc4(List<string> user_sids, out bool has_enroll_rights)
        {
            has_enroll_rights = false;

            var result = false;
            var owner_sid = SecurityDescriptor.GetOwner(typeof(SecurityIdentifier)).Value;

            if ((user_sids == null && SidUtil.IsLowPrivSid(owner_sid)) ||   // Is a low-privileged user owner of the template?
                (user_sids != null && user_sids.Contains(owner_sid)))       // Is a principal from our SID collection owner of the template?
            {
                result = true;
            }

            foreach (ActiveDirectoryAccessRule ace in SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            {
                if (ace.AccessControlType == AccessControlType.Allow)
                {
                    if ((user_sids == null && SidUtil.IsLowPrivSid(ace.IdentityReference.Value)) || // Does a low-privileged user have template rights?
                        (user_sids != null && user_sids.Contains(ace.IdentityReference.Value)))     // Does a principal from our SID collection have template rights?
                    {
                        var enrollment_type = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
                        var all_extend_type = "00000000-0000-0000-0000-000000000000";

                        if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll))
                            result = true;
                        else if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                            result = true;
                        else if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                            result = true;
                        else if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteProperty) && $"{ace.ObjectType}" == all_extend_type)
                            result = true;
                        
                        if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.ExtendedRight) && ($"{ace.ObjectType}" == enrollment_type || $"{ace.ObjectType}" == all_extend_type))
                            has_enroll_rights = true;
                    }
                }
            }

            if (result)
                Vulnerabilities.Add(4, "The template has insecure delegated permissions.");
        }

        private void CheckVulnerableEsc9()
        {
            var auth_oids = new List<string>()
            {
                CommonOids.ClientAuthentication,
                CommonOids.PKINITClientAuthentication,
                CommonOids.SmartcardLogon,
                CommonOids.AnyPurpose,
            };

            if ((ExtendedKeyUsage == null || !ExtendedKeyUsage.Any() || ExtendedKeyUsage.Any(o => auth_oids.Contains(o))) &&
                EnrollmentFlag.HasFlag(msPKIEnrollmentFlag.NO_SECURITY_EXTENSION))
            {
                var subject_alt_flags = new List<msPKICertificateNameFlag>()
                {
                    msPKICertificateNameFlag.SUBJECT_ALT_REQUIRE_UPN,
                    msPKICertificateNameFlag.SUBJECT_ALT_REQUIRE_SPN,
                    msPKICertificateNameFlag.SUBJECT_ALT_REQUIRE_DNS
                };

                if (subject_alt_flags.Any(flag => CertificateNameFlag.HasFlag(flag)))
                    Vulnerabilities.Add(9, "The template has a client authentication EKU and no security extension.");
                else
                    Vulnerabilities.Add(9, "The template has a client authentication EKU and no security extension, but only works with ESC6.");
            }
        }

        private void CheckVulnerableEsc13()
        {
            var auth_oids = new List<string>()
            {
                CommonOids.ClientAuthentication,
                CommonOids.PKINITClientAuthentication,
                CommonOids.SmartcardLogon,
            };

            if (ExtendedKeyUsage != null && ExtendedKeyUsage.Any(o => auth_oids.Contains(o)) && 
                IssuancePolicies != null && IssuancePolicies.Any(o => o.GroupLink != null))
            {
                Vulnerabilities.Add(13, $"The template has client authentication and an issuance policy linked to one or more domain group(s).");
            }
        }

        private void CheckVulnerableEsc15()
        {
            if (SchemaVersion == 1 && CertificateNameFlag.HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT))
                Vulnerabilities.Add(15, "The template has schema version 1 and allows enrollees to supply subject.");
        }
    }
}
