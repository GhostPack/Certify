using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Certify.Domain
{
    class PKIObjectACE
    {
        public string? Type { get; }
        public string? Rights { get; }
        public Guid? ObjectType { get; }
        public string? Principal { get; }

        public PKIObjectACE(AccessControlType? type, ActiveDirectoryRights? rights, Guid? objectType, string? principal)
        {
            Type = type.ToString();
            Rights = rights.ToString();
            ObjectType = objectType;
            Principal = principal;
        }
    }

    class PKIObjectACL
    {
        public string? Owner { get; }
        public List<PKIObjectACE>? ACEs { get; }

        public PKIObjectACL(ActiveDirectorySecurity? securityDescriptor)
        {
            Owner = ((SecurityIdentifier)securityDescriptor.GetOwner(typeof(SecurityIdentifier))).Value.ToString();
            var rules = securityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));
            ACEs = new List<PKIObjectACE>();

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var ace = new PKIObjectACE(
                    rule.AccessControlType,
                    (ActiveDirectoryRights)rule.ActiveDirectoryRights,
                    rule.ObjectType,
                    ((SecurityIdentifier)rule.IdentityReference).Value.ToString()
                ); ;

                ACEs.Add(ace);
            }
        }
    }

    class PKIObjectDTO
    {
        // used for JSON serialization
        public string? Name { get; }
        public string? DomainName { get; }
        public string? DistinguishedName { get; }

        public PKIObjectACL? ACL { get; }

        public PKIObjectDTO(PKIObject? pkiObject)
        {
            var securityDescriptor = pkiObject.SecurityDescriptor;

            Name = pkiObject?.Name;
            DomainName = pkiObject?.DomainName;
            DistinguishedName = pkiObject?.DistinguishedName;

            if (securityDescriptor == null)
            {
                ACL = null;
            }
            else
            {
                ACL = new PKIObjectACL(securityDescriptor);
            }
        }
    }

    class PKIObject : ADObject
    {
        public PKIObject(string name, string domainName, string distinguishedName, ActiveDirectorySecurity securityDescriptor)
            : base(securityDescriptor)
        {
            Name = name;
            DomainName = domainName;
            DistinguishedName = distinguishedName;
        }
        public string? Name { get; }
        public string? DomainName { get; }
        public string? DistinguishedName { get; }
    }
}
