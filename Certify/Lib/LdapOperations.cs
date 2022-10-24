using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Certify.Domain;

namespace Certify.Lib
{
    class LdapOperations
    {
        private readonly LdapSearchOptions _searchOptions;
        private string? _configurationPath = null;
        private string? _ldapServer = null;

        public string ConfigurationPath
        {
            get
            {
                if (_configurationPath == null)
                {
                    _configurationPath = GetConfigurationPath();
                }

                return _configurationPath;
            }

            set => _configurationPath = value;
        }

        public string LdapServer
        {
            get
            {
                if (_searchOptions.LdapServer == null)
                {
                    _ldapServer = "";
                }
                else
                {
                    _ldapServer = $"{_searchOptions.LdapServer}/";
                }

                return _ldapServer;
            }

            set => _ldapServer = value;
        }

        public LdapOperations()
        {
            _searchOptions = new LdapSearchOptions();
        }
        public LdapOperations(LdapSearchOptions searchOptions)
        {
            _searchOptions = searchOptions;
        }

        private string GetConfigurationPath()
        {
            var rootDse = _searchOptions.Domain == null
                ? new DirectoryEntry("LDAP://RootDSE")
                : new DirectoryEntry($"LDAP://{_searchOptions.Domain}/RootDSE");

            return $"{rootDse.Properties["configurationNamingContext"][0]}";
        }

        public IEnumerable<PKIObject> GetPKIObjects()
        {
            var pkiObjects = new List<PKIObject>();

            // Container location per MS-WCCE 2.2.2.11.2 Enrollment Services Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3ec073ec-9b91-4bee-964e-56f22a93a28c
            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Public Key Services,CN=Services,{ConfigurationPath}");

            var ds = new DirectorySearcher(root)
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner
            };

            var results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var distinguishedName = sr.Path;
                var sd = ParseSecurityDescriptor(sr);

                var pkiObject = new PKIObject(
                    name,
                    domainName,
                    distinguishedName,
                    sd
                );

                pkiObjects.Add(pkiObject);
            }

            // now we want to also find/enumerate the ACLs on all systems hosting CAs
            var enterpriseCAs = GetEnterpriseCAs();
            if (enterpriseCAs.Count() > 0)
            {
                var caDNSnames = new List<string>();
                foreach (var enterpriseCA in enterpriseCAs)
                {
                    caDNSnames.Add($"(dnshostname={enterpriseCA.DnsHostname})");
                }
                var caNameFilter = $"(|{ String.Join("", caDNSnames)})";

                var caDS = new DirectorySearcher()
                {
                    SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner,
                    Filter = caNameFilter
                };
                var caResults = caDS.FindAll();

                foreach (SearchResult sr in caResults)
                {
                    var name = ParseSamAccountName(sr);
                    var domainName = ParseDomainName(sr);
                    var distinguishedName = sr.Path;
                    var sd = ParseSecurityDescriptor(sr);

                    var pkiObject = new PKIObject(
                        name,
                        domainName,
                        distinguishedName,
                        sd
                    );

                    pkiObjects.Add(pkiObject);
                }
            }

            return pkiObjects;
        }


        public IEnumerable<EnterpriseCertificateAuthority> GetEnterpriseCAs(string? caName = null)
        {
            var cas = new List<EnterpriseCertificateAuthority>();

            // Container location per MS-WCCE 2.2.2.11.2 Enrollment Services Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3ec073ec-9b91-4bee-964e-56f22a93a28c
            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Enrollment Services,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root);

            if (caName == null) ds.Filter = "(objectCategory=pKIEnrollmentService)";
            else
            {
                var parts = caName.Split('\\');
                var caSimpleName = parts[parts.Length - 1];
                ds.Filter = $"(&(objectCategory=pKIEnrollmentService)(name={caSimpleName}))";
            }
            var results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var guid = ParseGuid(sr);
                var dnsHostname = ParseDnsHostname(sr);
                var flags = ParsePkiCertificateAuthorityFlags(sr);
                var certs = ParseCaCertificate(sr);
                var sd = ParseSecurityDescriptor(sr);

                var templates = new List<string>();
                foreach (var template in sr.Properties["certificatetemplates"])
                {
                    templates.Add($"{template}");
                }

                var ca = new EnterpriseCertificateAuthority(
                    sr.Path,
                    name,
                    domainName,
                    guid,
                    dnsHostname,
                    flags,
                    certs,
                    sd,
                    templates
                );

                cas.Add(ca);
            }

            return cas;
        }


        public CertificateAuthority GetNtAuthCertificates()
        {
            // Container location per MS-WCCE 2.2.2.11.3 NTAuthCertificates Object
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/f1004c63-8508-43b5-9b0b-ee7880183745
            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root);
            ds.Filter = "(objectClass=certificationAuthority)";

            var results = ds.FindAll();

            if (results.Count != 1) throw new Exception("More than one NTAuthCertificate object found");

            var sr = results[0];

            var name = ParseName(sr);
            var domainName = ParseDomainName(sr);
            var guid = ParseGuid(sr);
            var sd = ParseSecurityDescriptor(sr);
            var certs = ParseCaCertificate(sr);

            return new CertificateAuthority(
                sr.Path,
                name,
                domainName,
                guid,
                null,
                certs,
                sd
            );
        }


        public IEnumerable<CertificateTemplate> GetCertificateTemplates()
        {
            var templates = new List<CertificateTemplate>();

            // Container location per MS-WCCE 2.2.2.11.1 Certificates Templates Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44
            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certificate Templates,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root)
            {
                SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner,
                Filter = "(objectclass=pKICertificateTemplate)"
            };

            var results = ds.FindAll();

            if (results.Count == 0)
            {
                return templates;
            }

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var guid = ParseGuid(sr);
                var schemaVersion = ParseSchemaVersion(sr);
                var displayName = ParseDisplayName(sr);
                var validityPeriod = ParsePkiExpirationPeriod(sr);
                var renewalPeriod = ParsePkiOverlapPeriod(sr);
                var templateOid = ParsePkiCertTemplateOid(sr);
                var enrollmentFlag = ParsePkiEnrollmentFlag(sr);
                var certificateNameFlag = ParsePkiCertificateNameFlag(sr);

                var ekus = ParseExtendedKeyUsages(sr);
                var authorizedSignatures = ParseAuthorizedSignatures(sr);
                var raApplicationPolicies = ParseRaApplicationPolicies(sr);
                var issuancePolicies = ParseIssuancePolicies(sr);

                var securityDescriptor = ParseSecurityDescriptor(sr);

                var applicationPolicies = ParseCertificateApplicationPolicies(sr);

                templates.Add(new CertificateTemplate(
                    sr.Path,
                    name,
                    domainName,
                    guid,
                    schemaVersion,
                    displayName,
                    validityPeriod,
                    renewalPeriod,
                    templateOid,
                    certificateNameFlag,
                    enrollmentFlag,
                    ekus,
                    authorizedSignatures,
                    raApplicationPolicies,
                    issuancePolicies,
                    securityDescriptor,
                    applicationPolicies
                ));
            }

            return templates;
        }


        public List<CertificateAuthority> GetRootCAs()
        {
            var cas = new List<CertificateAuthority>();

            // Container location per MS-WCCE 2.2.2.11.4 Certification Authorities Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/6c446198-f670-4885-97a9-cbc50a2b96b4
            var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certification Authorities,CN=Public Key Services,CN=Services,{ConfigurationPath}");
            var ds = new DirectorySearcher(root);

            ds.Filter = "(objectCategory=certificationAuthority)";

            var results = ds.FindAll();

            foreach (SearchResult sr in results)
            {
                var name = ParseName(sr);
                var domainName = ParseDomainName(sr);
                var guid = ParseGuid(sr);
                var sd = ParseSecurityDescriptor(sr);
                var certs = ParseCaCertificate(sr);

                var ca = new CertificateAuthority(
                    sr.Path,
                    name,
                    domainName,
                    guid,
                    null,
                    certs,
                    sd
                );

                cas.Add(ca);
            }

            return cas;
        }


        private static PkiCertificateAuthorityFlags? ParsePkiCertificateAuthorityFlags(SearchResult sr)
        {
            if (!sr.Properties.Contains("flags"))
                return null;

            return (PkiCertificateAuthorityFlags)Enum.Parse(typeof(PkiCertificateAuthorityFlags), sr.Properties["flags"][0].ToString());
        }


        private static string? ParseDnsHostname(SearchResult sr)
        {
            if (!sr.Properties.Contains("dnshostname"))
                return null;

            return sr.Properties["dnshostname"][0].ToString();
        }


        private static ActiveDirectorySecurity? ParseSecurityDescriptor(SearchResult sr)
        {
            if (!sr.Properties.Contains("ntsecuritydescriptor"))
            {
                return null;
            }

            var sdbytes = (byte[])sr.Properties["ntsecuritydescriptor"][0];
            var sd = new ActiveDirectorySecurity();
            sd.SetSecurityDescriptorBinaryForm(sdbytes);

            return sd;
        }


        private static List<X509Certificate2>? ParseCaCertificate(SearchResult sr)
        {
            if (!sr.Properties.Contains("cacertificate"))
                return null;

            var certs = new List<X509Certificate2>();
            foreach (var certBytes in sr.Properties["cacertificate"])
            {
                var cert = new X509Certificate2((byte[])certBytes);
                certs.Add(cert);
            }

            return certs;
        }


        private List<string>? ParseCertificateTemplate(SearchResult sr)
        {
            if (!sr.Properties.Contains("certificatetemplates"))
                return null;

            var templates = new List<string>();
            foreach (var template in sr.Properties["certificatetemplates"])
            {
                templates.Add($"{template}");
            }

            return templates;
        }


        private msPKICertificateNameFlag? ParsePkiCertificateNameFlag(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-certificate-name-flag"))
                return null;

            return ParseIntToEnum<msPKICertificateNameFlag>(sr.Properties["mspki-certificate-name-flag"][0].ToString());
        }


        private msPKIEnrollmentFlag? ParsePkiEnrollmentFlag(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-enrollment-flag"))
                return null;

            return ParseUIntToEnum<msPKIEnrollmentFlag>(sr.Properties["mspki-enrollment-flag"][0].ToString());
        }


        private static string? ParseDisplayName(SearchResult sr)
        {
            if (!sr.Properties.Contains("displayname"))
                return null;

            return sr.Properties["displayname"][0].ToString();
        }


        private static string? ParseName(SearchResult sr)
        {
            if (!sr.Properties.Contains("name"))
                return null;

            return sr.Properties["name"][0].ToString();
        }


        private static string? ParseSamAccountName(SearchResult sr)
        {
            if (!sr.Properties.Contains("samaccountname"))
                return null;

            return sr.Properties["samaccountname"][0].ToString();
        }


        private static string? ParseDomainName(SearchResult sr)
        {
            if (!sr.Properties.Contains("distinguishedname"))
                return null;

            return DisplayUtil.GetDomainFromDN(sr.Properties["distinguishedname"][0].ToString());
        }


        private static string? ParseDistinguishedName(SearchResult sr)
        {
            if (!sr.Properties.Contains("distinguishedname"))
                return null;

            return sr.Properties["distinguishedname"][0].ToString();
        }


        private static Guid? ParseGuid(SearchResult sr)
        {
            if (!sr.Properties.Contains("objectguid"))
                return null;

            return new Guid((System.Byte[])sr.Properties["objectguid"][0]);
        }


        private static int? ParseSchemaVersion(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-template-schema-version"))
                return null;

            var schemaVersion = 0;
            int.TryParse(sr.Properties["mspki-template-schema-version"][0].ToString(), out schemaVersion);
            return schemaVersion;
        }


        private static Oid? ParsePkiCertTemplateOid(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-cert-template-oid"))
                return null;

            return new Oid(sr.Properties["mspki-cert-template-oid"][0].ToString());
        }


        private string? ParsePkiOverlapPeriod(SearchResult sr)
        {
            if (!sr.Properties.Contains("pKIOverlapPeriod"))
                return null;

            return ConvertPKIPeriod((byte[])sr.Properties["pKIOverlapPeriod"][0]);
        }

        private string? ParsePkiExpirationPeriod(SearchResult sr)
        {
            if (!sr.Properties.Contains("pKIExpirationPeriod"))
                return null;

            return ConvertPKIPeriod((byte[])sr.Properties["pKIExpirationPeriod"][0]);
        }

        private static IEnumerable<string>? ParseExtendedKeyUsages(SearchResult sr)
        {
            if (!sr.Properties.Contains("pkiextendedkeyusage"))
                return null;

            return from object oid in sr.Properties["pkiextendedkeyusage"] select oid.ToString();
        }

        private static int? ParseAuthorizedSignatures(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-ra-signature"))
                return null;

            var authorizedSignatures = 0;
            var temp = sr.Properties["mspki-ra-signature"][0].ToString();
            if (!string.IsNullOrEmpty(temp))
            {
                int.TryParse(temp, out authorizedSignatures);
            }

            return authorizedSignatures;
        }

        private static IEnumerable<string>? ParseRaApplicationPolicies(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-ra-application-policies"))
                return null;

            return from object oid in sr.Properties["mspki-ra-application-policies"] select oid.ToString();
        }

        private static IEnumerable<string>? ParseIssuancePolicies(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-ra-policies"))
                return null;

            return from object oid in sr.Properties["mspki-ra-policies"] select oid.ToString();
        }

        private static IEnumerable<string>? ParseCertificateApplicationPolicies(SearchResult sr)
        {
            if (!sr.Properties.Contains("mspki-certificate-application-policy"))
                return null;

            return from object oid in sr.Properties["mspki-certificate-application-policy"] select oid.ToString();
        }

        private T ParseUIntToEnum<T>(string value)
        {
            var uintVal = Convert.ToUInt32(value);

            return (T)Enum.Parse(typeof(T), uintVal.ToString());

        }

        private T ParseIntToEnum<T>(string value)
        {
            var intVal = Convert.ToInt32(value);
            var uintVal = unchecked((uint)intVal);

            return (T)Enum.Parse(typeof(T), uintVal.ToString());
        }

        private string ConvertPKIPeriod(byte[] bytes)
        {
            // ref: https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx
            try
            {
                Array.Reverse(bytes);
                var temp = BitConverter.ToString(bytes).Replace("-", "");
                var value = Convert.ToInt64(temp, 16) * -.0000001;

                if ((value % 31536000 == 0) && (value / 31536000) >= 1)
                {
                    if ((value / 31536000) == 1)
                    {
                        return "1 year";
                    }

                    return $"{value / 31536000} years";
                }
                else if ((value % 2592000 == 0) && (value / 2592000) >= 1)
                {
                    if ((value / 2592000) == 1)
                    {
                        return "1 month";
                    }
                    else
                    {
                        return $"{value / 2592000} months";
                    }
                }
                else if ((value % 604800 == 0) && (value / 604800) >= 1)
                {
                    if ((value / 604800) == 1)
                    {
                        return "1 week";
                    }
                    else
                    {
                        return $"{value / 604800} weeks";
                    }
                }
                else if ((value % 86400 == 0) && (value / 86400) >= 1)
                {
                    if ((value / 86400) == 1)
                    {
                        return "1 day";
                    }
                    else
                    {
                        return $"{value / 86400} days";
                    }
                }
                else if ((value % 3600 == 0) && (value / 3600) >= 1)
                {
                    if ((value / 3600) == 1)
                    {
                        return "1 hour";
                    }
                    else
                    {
                        return $"{value / 3600} hours";
                    }
                }
                else
                {
                    return "";
                }
            }
            catch (Exception)
            {
                return "ERROR";
            }
        }
    }
}
