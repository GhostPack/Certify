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

    class PKIObject : ADObject
    {
        public PKIObject(string? name, string? domainName, string distinguishedName, ActiveDirectorySecurity? securityDescriptor)
            : base(distinguishedName, securityDescriptor)
        {
            Name = name;
            DomainName = domainName;
            DistinguishedName = distinguishedName;
        }
        public string? Name { get; }
        public string? DomainName { get; }
    }
}
