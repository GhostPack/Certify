
namespace Certify.Domain
{
    public static class CommonOids
    {
        public static string AnyPurpose = "2.5.29.37.0";
        public static string ClientAuthentication = "1.3.6.1.5.5.7.3.2";
        public static string PKINITClientAuthentication = "1.3.6.1.5.2.3.4";
        public static string SmartcardLogon = "1.3.6.1.4.1.311.20.2.2";
        public static string CertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1";

        public static string UserPrincipalName = "1.3.6.1.4.1.311.20.2.3"; // szOID_NT_PRINCIPAL_NAME
        public static string NtdsCaSecurityExt = "1.3.6.1.4.1.311.25.2"; // szOID_NTDS_CA_SECURITY_EXT
      
        public static string ApplicationPolicies = "1.3.6.1.4.1.311.21.10";
        public static string CertificatePolicies = "2.5.29.32";
    };
}
