using System;
using System.DirectoryServices;
using System.Security.AccessControl;

namespace Certify.Domain
{
    class PKIObjectACE
    {
        public string Type { get; }
        public string Rights { get; }
        public Guid ObjectType { get; }
        public string Principal { get; }

        public PKIObjectACE(AccessControlType access_type, ActiveDirectoryRights rights, Guid object_type, string principal)
        {
            Type = access_type.ToString();
            Rights = rights.ToString();
            ObjectType = object_type;
            Principal = principal;
        }
    }

    class PKIObject : ADObject
    {
        public string Name { get; }
        public string DomainName { get; }

        public PKIObject(string dn, string name, string domain, ActiveDirectorySecurity security_descriptor)
            : base(dn, security_descriptor)
        {
            Name = name;
            DomainName = domain;
        }
    }
}
