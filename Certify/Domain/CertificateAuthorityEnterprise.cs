using System;
using System.Collections.Generic;
using System.Data;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Certify.Lib;
using Microsoft.Win32;

namespace Certify.Domain
{
    [Flags]
    enum EditFlags : uint
    {
        ATTRIBUTE_EKU = 0x00008000,
        ATTRIBUTE_SUBJECTALTNAME2 = 0x00040000,
    }

    [Flags]
    enum InterfaceFlags : uint
    {
        NO_REMOTE_ICERTREQUEST = 0x00000002, // The CA will not issue any certificates or hold pending any requests for remote users.
        NO_LOCAL_ICERTREQUEST = 0x00000004, // The CA will not issue any certificates or hold pending any requests for local users.
        NO_RPC_ICERTREQUEST = 0x00000008, // The CA will not issue any certificates or hold pending any requests for callers using the ICertPassage interface.
        NO_REMOTE_ICERTADMIN = 0x00000010, // No access to Certificate Services Remote Administration Protocol methods for remote callers.
        NO_LOCAL_ICERTADMIN = 0x00000020, // No access to Certificate Services Remote Administration Protocol methods for local callers.
        NO_REMOTE_ICERTADMIN_BACKUP = 0x00000040, // The CA restricts access to the backup-related methods of this protocol for remote callers.
        NO_LOCAL_ICERTADMIN_BACKUP = 0x00000080, // The CA restricts access to the backup-related methods of this protocol for local callers.
        NO_SNAPSHOT_BACKUP = 0x00000100, // The database files cannot be backed up using a mechanism other than the methods of this interface.
        ENFORCE_ENCRYPT_ICERTREQUEST = 0x00000200, // RPC_C_AUTHN_LEVEL_PKT_PRIVACY is to be defined for all RPC connections to the server for certificate-request operations.
        ENFORCE_ENCRYPT_ICERTADMIN = 0x00000400, // RPC_C_AUTHN_LEVEL_PKT_PRIVACY is to be defined for all RPC connections to the server for certificate administrative operations.
    }

    class CertificateAuthorityEnterprise : CertificateAuthority
    {
        public List<string> Templates { get; }
        public string DnsHostname { get; }
        public string FullName => $"{DnsHostname}\\{Name}";

        public string UserSpecifiedEku { get; }
        public string UserSpecifiedSan { get; }

        public string RpcRequestEncryption { get; }
        public List<string> RpcRequestRestrictions { get; } = new List<string>();

        public List<string> DisabledExtensions { get; }
        public Dictionary<int, string> Vulnerabilities { get; } = new Dictionary<int, string>();

        public CertificateAuthorityEnterprise(string dn, string name, string domain, Guid guid, string dns_hostname, PkiCertificateAuthorityFlags flags, 
            List<X509Certificate2> certificates, ActiveDirectorySecurity security_descriptor, List<string> templates, List<string> user_sids)
            : base(dn, name, domain, guid, flags, certificates, security_descriptor)
        {
            DnsHostname = dns_hostname;
            Templates = templates;

            try
            {
                var edit_flags = GetEditFlags();
                UserSpecifiedSan = GetFlagState(edit_flags, EditFlags.ATTRIBUTE_SUBJECTALTNAME2);
            }
            catch (Exception e)
            {
                UserSpecifiedSan = e.Message;
            }

            try
            {
                var interface_flags = GetInterfaceFlags();

                RpcRequestEncryption = GetFlagState(interface_flags, InterfaceFlags.ENFORCE_ENCRYPT_ICERTREQUEST);

                var request_restrictions = new List<Tuple<InterfaceFlags, string>>()
                {
                    new Tuple<InterfaceFlags, string>(InterfaceFlags.NO_REMOTE_ICERTREQUEST, "No Remote"),
                    new Tuple<InterfaceFlags, string>(InterfaceFlags.NO_LOCAL_ICERTREQUEST, "No Local"),
                    new Tuple<InterfaceFlags, string>(InterfaceFlags.NO_RPC_ICERTREQUEST, "No Access"),
                };

                foreach (var r in request_restrictions)
                {
                    if (TestFlagState(interface_flags, r.Item1))
                        RpcRequestRestrictions.Add(r.Item2);
                }
            }
            catch (Exception e)
            {
                RpcRequestEncryption = e.Message;
            }

            try
            {
                DisabledExtensions = GetDisableExtensionList().Where(s => !string.IsNullOrEmpty(s)).ToList();
            }
            catch (Exception)
            {
                DisabledExtensions = new List<string>();
            }

            FindVulnerabilities(user_sids);
        }

        private void FindVulnerabilities(List<string> user_sids)
        {
            CheckVulnerableEsc6();
            CheckVulnerableEsc7(user_sids);
            CheckVulnerableEsc8();
            CheckVulnerableEsc11();
            CheckVulnerableEsc16();
        }

        private void CheckVulnerableEsc6()
        {
            if (UserSpecifiedSan == "Enabled")
                Vulnerabilities.Add(6, "The CA allows enrollees to specify SANs.");
        }

        private void CheckVulnerableEsc7(List<string> user_sids)
        {
            var security_descriptor = GetServerSecurityFromRegistry();
            var vulnerable = false;

            if (security_descriptor != null)
            {
                var owner_sid = security_descriptor.GetOwner(typeof(SecurityIdentifier)).Value;

                if ((user_sids == null && SidUtil.IsLowPrivSid(owner_sid)) ||   // Is a low-privileged user owner of the certificate authority?
                    (user_sids != null && user_sids.Contains(owner_sid)))       // Is a principal from our SID collection owner of the certificate authority?
                {
                    vulnerable = true;
                }

                foreach (ActiveDirectoryAccessRule ace in security_descriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    var rights = (CertificationAuthorityRights)ace.ActiveDirectoryRights;

                    if (rights.HasFlag(CertificationAuthorityRights.ManageCA))
                    {
                        if ((user_sids == null && SidUtil.IsLowPrivSid(ace.IdentityReference.Value)) || // Does a low-privileged user have the "Manage CA" role?
                            (user_sids != null && user_sids.Contains(ace.IdentityReference.Value)))     // Does a principal from our SID collection have the "Manage CA" role?
                        {
                            vulnerable = true;
                        }
                    }
                    
                    if (rights.HasFlag(CertificationAuthorityRights.ManageCertificates))
                    {
                        if ((user_sids == null && SidUtil.IsLowPrivSid(ace.IdentityReference.Value)) || // Does a low-privileged user have the "Manage Certificates" role?
                            (user_sids != null && user_sids.Contains(ace.IdentityReference.Value)))     // Does a principal from our SID collection have the "Manage Certificates" role?
                        {
                            vulnerable = true;
                        }
                    }
                }
            }

            if (vulnerable)
                Vulnerabilities.Add(7, "The CA has insecure delegated security roles or permissions.");
        }

        private void CheckVulnerableEsc8()
        {
            var http_url = $"http://{DnsHostname}/certsrv/";
            var https_url = $"https://{DnsHostname}/certsrv/";

            if (HttpUtil.AuthWithChannelBinding(http_url) && HttpUtil.AuthWithoutChannelBinding(http_url))
                Vulnerabilities.Add(8, "The CA supports HTTP web enrollment without channel binding.");
            else if (HttpUtil.AuthWithChannelBinding(https_url) && HttpUtil.AuthWithoutChannelBinding(https_url))
                Vulnerabilities.Add(8, "The CA supports HTTPS web enrollment without channel binding.");
        }

        private void CheckVulnerableEsc11()
        {
            if (RpcRequestEncryption == "Disabled")
                Vulnerabilities.Add(11, "The CA does not enforce encryption on the ICertPassage RPC interface.");
        }

        private void CheckVulnerableEsc16()
        {
            if (DisabledExtensions.Contains(CommonOids.NtdsCaSecurityExt))
                Vulnerabilities.Add(16, "The CA has disabled the security extension.");
        }

        public ActiveDirectorySecurity GetServerSecurityFromRegistry()
        {
            var security = GetRemoteRegistryKey<byte[]>($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}", "Security");

            if (security != null)
            {
                var security_descriptor = new ActiveDirectorySecurity();
                security_descriptor.SetSecurityDescriptorBinaryForm(security, AccessControlSections.All);
                return security_descriptor;
            }

            return null;
        }

        public RawSecurityDescriptor GetEnrollmentAgentSecurity()
        {
            var rights = GetRemoteRegistryKey<byte[]>($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}", "EnrollmentAgentRights");
            return rights == null ? null : new RawSecurityDescriptor(rights, 0);
        }

        private EditFlags GetEditFlags()
        {
            return (EditFlags)GetRemoteRegistryKey<int>($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags");
        }

        private InterfaceFlags GetInterfaceFlags()
        {
            return (InterfaceFlags)GetRemoteRegistryKey<int>($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}", "InterfaceFlags");
        }

        private string[] GetDisableExtensionList()
        {
            return GetRemoteRegistryKey<string[]>($"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{Name}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList");
        }

        private T GetRemoteRegistryKey<T>(string key_name, string value_name)
        {
            if (this.DnsHostname == null)
                throw new NullReferenceException("DnsHostname is null");

            if (base.Name == null)
                throw new NullReferenceException("Name is null");

            try
            {
                // NOTE: this appears to work even if admin rights aren't available on the remote CA server
                using (var base_key = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, DnsHostname))
                {
                    try
                    {
                        using (var sub_key = base_key.OpenSubKey(key_name))
                        {
                            return (T)sub_key.GetValue(value_name);
                        }
                    }
                    catch (SecurityException e)
                    {
                        throw new Exception($"Could not access the '{value_name}' registry value: {e.Message}");
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Could not connect to the HKLM hive - {e.Message}");
                return default;
            }
        }

        private string GetFlagState<T>(T flags, T flag) where T : Enum
        {
            if (TestFlagState(flags, flag))
                return "Enabled";
            else
                return "Disabled";
        }

        private bool TestFlagState<T>(T flags, T flag) where T : Enum
        {
            return flags.HasFlag(flag);
        }

        public CertificateAuthorityWebServices GetWebServices()
        {
            if (DnsHostname == null)
                throw new NullReferenceException("DnsHostname is null");

            var webservices = new CertificateAuthorityWebServices();
            var protocols = new List<string>() { "http://", "https://" };

            foreach (var protocol in protocols)
            {
                var url_legacy_asp_enrollment = $"{protocol}{DnsHostname}/certsrv/";

                if (UrlExists(url_legacy_asp_enrollment, "NTLM"))
                    webservices.LegacyAspEnrollmentUrls.Add(url_legacy_asp_enrollment);

                var url_enrollment_webservice = $"{protocol}{DnsHostname}/{Name}_CES_Kerberos/service.svc";

                if (UrlExists(url_enrollment_webservice))
                    webservices.EnrollmentWebServiceUrls.Add(url_enrollment_webservice);

                var url_enrollment_policy_webservice = $"{protocol}{DnsHostname}/ADPolicyProvider_CEP_Kerberos/service.svc";

                if (UrlExists(url_enrollment_policy_webservice))
                    webservices.EnrollmentPolicyWebServiceUrls.Add(url_enrollment_policy_webservice);

                var url_ndes_enrollment = $"{protocol}{DnsHostname}/certsrv/mscep/";

                if (UrlExists(url_ndes_enrollment))
                    webservices.NetworkDeviceEnrollmentServiceUrls.Add(url_ndes_enrollment);
            }

            return webservices;
        }

        public static bool UrlExists(string url, string auth_type = "Negotiate")
        {
            var request = WebRequest.CreateHttp(url);
            request.Timeout = 3000;
            request.Credentials = new CredentialCache
            {
                { new Uri(url), auth_type, CredentialCache.DefaultNetworkCredentials }
            };
            request.ServerCertificateValidationCallback += (sender, certificate, chain, errors) => true;

            try
            {
                var valid_responses = new List<HttpStatusCode>()
                {
                    HttpStatusCode.OK,
                    HttpStatusCode.Unauthorized,
                    HttpStatusCode.Forbidden
                };

                using (var response = (HttpWebResponse)request.GetResponse())
                    return valid_responses.Contains(response.StatusCode);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
