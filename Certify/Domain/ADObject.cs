using System.DirectoryServices;

namespace Certify.Domain
{
    public class ADObject
    {
        public string DistinguishedName { get; set; }
        public ActiveDirectorySecurity? SecurityDescriptor { get; set; }
        public ADObject(string distinguishedName, ActiveDirectorySecurity? securityDescriptor)
        {
            DistinguishedName = distinguishedName;
            SecurityDescriptor = securityDescriptor;    
        }
    }
}
