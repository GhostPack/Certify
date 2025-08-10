using System.Collections.Generic;

namespace Certify.Domain
{
    public class CertificateAuthorityWebServices
    {
        public List<string> LegacyAspEnrollmentUrls { get; set; } = new List<string>();
        public List<string> EnrollmentWebServiceUrls { get; set; } = new List<string>();
        public List<string> EnrollmentPolicyWebServiceUrls { get; set; } = new List<string>();
        public List<string> NetworkDeviceEnrollmentServiceUrls { get; set; } = new List<string>();
    }
}
