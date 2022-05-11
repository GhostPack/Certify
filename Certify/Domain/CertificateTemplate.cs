using System;
using System.Collections.Generic;
using System.DirectoryServices;
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
        CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80,
        PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040,
        USER_INTERACTION_REQUIRED = 0x00000100,
        ADD_TEMPLATE_NAME = 0x200,
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
        public string? Type { get; }
        public string? Rights { get; }
        public Guid? ObjectType { get; }
        public string? Principal { get; }

        public CertificateTemplateACE(AccessControlType? type, ActiveDirectoryRights? rights, Guid? objectType, string? principal)
        {
            Type = type.ToString();
            Rights = rights.ToString();
            ObjectType = objectType;
            Principal = principal;
        }
    }

    class CertificateTemplateACL
    {
        public string? Owner { get; }
        public List<CertificateTemplateACE>? ACEs { get; }

        public CertificateTemplateACL(ActiveDirectorySecurity securityDescriptor)
        {
            Owner = ((SecurityIdentifier)securityDescriptor.GetOwner(typeof(SecurityIdentifier))).Value.ToString();
            var rules = securityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));
            ACEs = new List<CertificateTemplateACE>();

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var ace = new CertificateTemplateACE(
                    rule.AccessControlType,
                    (ActiveDirectoryRights)rule.ActiveDirectoryRights,
                    rule.ObjectType,
                    ((SecurityIdentifier)rule.IdentityReference).Value.ToString()
                ); ;

                ACEs.Add(ace);
            }
        }
    }

    class CertificateTemplateDTO
    {
        // used for JSON serialization
        public string? Name { get; }
        public string? DomainName { get; }
        public string? DisplayName { get; }
        public Guid? Guid { get; }
        public int? SchemaVersion { get; }
        public string? ValidityPeriod { get; }
        public string? RenewalPeriod { get; }
        public Oid? Oid { get; }
        public msPKICertificateNameFlag? CertificateNameFlag { get; }
        public msPKIEnrollmentFlag? EnrollmentFlag { get; }
        public IEnumerable<string>? ExtendedKeyUsage { get; }
        public int? AuthorizedSignatures { get; }
        public IEnumerable<string>? ApplicationPolicies { get; }
        public IEnumerable<string>? IssuancePolicies { get; }
        public IEnumerable<string>? CertificateApplicationPolicies { get; }

        // vulnerability-related settings
        public bool? RequiresManagerApproval { get; }
        public bool? EnrolleeSuppliesSubject { get; }

        public CertificateTemplateACL? ACL { get; }

        public CertificateTemplateDTO(CertificateTemplate template)
        {
            var securityDescriptor = template.SecurityDescriptor;

            Name = template.Name;
            DomainName = template.DomainName;
            Guid = template.Guid;
            DisplayName = template.DisplayName;
            ValidityPeriod = template.ValidityPeriod;
            RenewalPeriod = template.RenewalPeriod;
            Oid = template.Oid;
            CertificateNameFlag = template.CertificateNameFlag;
            EnrollmentFlag = template.EnrollmentFlag;
            ExtendedKeyUsage = template.ExtendedKeyUsage;
            AuthorizedSignatures = template.AuthorizedSignatures;
            IssuancePolicies = template.IssuancePolicies;
            CertificateApplicationPolicies = template.ApplicationPolicies;

            var requiresManagerApproval = template.EnrollmentFlag != null && ((msPKIEnrollmentFlag)template.EnrollmentFlag).HasFlag(msPKIEnrollmentFlag.PEND_ALL_REQUESTS);
            var enrolleeSuppliesSubject = template.CertificateNameFlag != null && ((msPKICertificateNameFlag)template.CertificateNameFlag).HasFlag(msPKICertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT);

            RequiresManagerApproval = requiresManagerApproval;
            EnrolleeSuppliesSubject = enrolleeSuppliesSubject;

            if (securityDescriptor == null)
            {
                ACL = null;
            }
            else
            {
                ACL = new CertificateTemplateACL(securityDescriptor);
            }
        }
    }

    class CertificateTemplate : ADObject
    {
        public CertificateTemplate(string distinguishedName, string? name, string? domainName, Guid? guid, int? schemaVersion, string? displayName, string? validityPeriod, string? renewalPeriod, Oid? oid, msPKICertificateNameFlag? certificateNameFlag, msPKIEnrollmentFlag? enrollmentFlag, IEnumerable<string>? extendedKeyUsage, int? authorizedSignatures, IEnumerable<string>? raApplicationPolicies, IEnumerable<string>? issuancePolicies, ActiveDirectorySecurity? securityDescriptor, IEnumerable<string>? applicationPolicies)
            : base(distinguishedName, securityDescriptor)
        {
            Name = name;
            DomainName = domainName;
            Guid = guid;
            SchemaVersion = schemaVersion;
            DisplayName = displayName;
            ValidityPeriod = validityPeriod;
            RenewalPeriod = renewalPeriod;
            Oid = oid;
            CertificateNameFlag = certificateNameFlag;
            EnrollmentFlag = enrollmentFlag;
            ExtendedKeyUsage = extendedKeyUsage;
            AuthorizedSignatures = authorizedSignatures;
            RaApplicationPolicies = raApplicationPolicies;
            IssuancePolicies = issuancePolicies;
            ApplicationPolicies = applicationPolicies;
        }
        public string? Name { get; }
        public string? DomainName { get; }
        public Guid? Guid { get; }
        public int? SchemaVersion { get; }
        public string? DisplayName { get; }
        public string? ValidityPeriod { get; }
        public string? RenewalPeriod { get; }
        public Oid? Oid { get; }
        public msPKICertificateNameFlag? CertificateNameFlag { get; }
        public msPKIEnrollmentFlag? EnrollmentFlag { get; }
        public IEnumerable<string>? ExtendedKeyUsage { get; }
        public int? AuthorizedSignatures { get; }
        public IEnumerable<string>? RaApplicationPolicies { get; }
        public IEnumerable<string>? IssuancePolicies { get; }
        public IEnumerable<string>? ApplicationPolicies { get; }
    }
}
