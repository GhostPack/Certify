using System.DirectoryServices;

namespace Certify.Domain
{
    public class ADObject
    {
        public string DistinguishedName { get; set; }
        public ActiveDirectorySecurity SecurityDescriptor { get; set; }

        public ADObject(string dn, ActiveDirectorySecurity security_descriptor)
        {
            DistinguishedName = dn;
            SecurityDescriptor = security_descriptor;
        }
    }
}
