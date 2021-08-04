using System.DirectoryServices;

namespace Certify.Domain
{
    public class ADObject
    {
        public ActiveDirectorySecurity? SecurityDescriptor { get; set; }
        public ADObject(ActiveDirectorySecurity? securityDescriptor)
        {
            SecurityDescriptor = securityDescriptor;    
        }
    }
}
