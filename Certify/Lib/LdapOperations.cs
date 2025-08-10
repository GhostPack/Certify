using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using Certify.Domain;

namespace Certify.Lib
{
    class LdapOperations
    {
        public string ConfigurationPath { get; }
        public string LdapServer { get; }

        public LdapOperations()
            : this(null, null)
        {

        }

        public LdapOperations(string domain, string server)
        {
            string root_dse_path;

            if (domain == null)
                root_dse_path = "LDAP://RootDSE";
            else
                root_dse_path = $"LDAP://{domain}/RootDSE";

            using (var root_dse = new DirectoryEntry(root_dse_path))
                ConfigurationPath = $"{root_dse.Properties["configurationNamingContext"][0]}";

            if (server == null)
                LdapServer = string.Empty;
            else
                LdapServer = $"{server}/";
        }

        public IEnumerable<PKIObject> GetPKIObjects()
        {
            var pki_objects = new List<PKIObject>();

            // Container location per MS-WCCE 2.2.2.11.2 Enrollment Services Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3ec073ec-9b91-4bee-964e-56f22a93a28c

            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner })
                {
                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            pki_objects.Add(new PKIObject(
                                sr.Path,
                                LdapParser.ParseName(sr),
                                LdapParser.ParseDomainName(sr),
                                LdapParser.ParseSecurityDescriptor(sr)
                            ));
                        }

                        // now we want to also find/enumerate the ACLs on all systems hosting CAs
                        var ca_dns_names = new List<string>();

                        foreach (var enterprise_ca in GetEnterpriseCAs())
                            ca_dns_names.Add($"(dnshostname={enterprise_ca.DnsHostname})");

                        if (ca_dns_names.Count > 0)
                        {
                            var ca_name_filter = $"(|{string.Join("", ca_dns_names)})";

                            using (var ca_ds = new DirectorySearcher() { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner, Filter = ca_name_filter })
                            {
                                using (var ca_results = ca_ds.FindAll())
                                {
                                    foreach (SearchResult sr in ca_results)
                                    {
                                        pki_objects.Add(new PKIObject(
                                            sr.Path,
                                            LdapParser.ParseSamAccountName(sr),
                                            LdapParser.ParseDomainName(sr),
                                            LdapParser.ParseSecurityDescriptor(sr)
                                        ));
                                    }
                                }
                            }
                        }

                        return pki_objects;
                    }
                }
            }
        }

        public IEnumerable<CertificateAuthorityEnterprise> GetEnterpriseCAs(string ca_name = null, List<string> user_sids = null)
        {
            var cas = new List<CertificateAuthorityEnterprise>();

            // Container location per MS-WCCE 2.2.2.11.2 Enrollment Services Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/3ec073ec-9b91-4bee-964e-56f22a93a28c

            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Enrollment Services,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner })
                {
                    if (ca_name == null)
                        ds.Filter = "(objectCategory=pKIEnrollmentService)";
                    else
                        ds.Filter = $"(&(objectCategory=pKIEnrollmentService)(name={ca_name.Split('\\').Last()}))";

                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            cas.Add(new CertificateAuthorityEnterprise(
                                sr.Path,
                                LdapParser.ParseName(sr),
                                LdapParser.ParseDomainName(sr),
                                LdapParser.ParseGuid(sr),
                                LdapParser.ParseDnsHostname(sr),
                                LdapParser.ParsePkiCertificateAuthorityFlags(sr),
                                LdapParser.ParseCaCertificate(sr),
                                LdapParser.ParseSecurityDescriptor(sr),
                                LdapParser.ParseCertificateTemplate(sr),
                                user_sids
                            ));
                        }

                        return cas;
                    }
                }
            }
        }

        public CertificateAuthority GetNtAuthCertificates()
        {
            // Container location per MS-WCCE 2.2.2.11.3 NTAuthCertificates Object
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/f1004c63-8508-43b5-9b0b-ee7880183745

            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { Filter = "(objectClass=certificationAuthority)" })
                {
                    using (var results = ds.FindAll())
                    {
                        if (results.Count != 1)
                            throw new Exception("More than one NTAuthCertificate object found");

                        var sr = results[0];

                        return new CertificateAuthority(
                            sr.Path,
                            LdapParser.ParseName(sr),
                            LdapParser.ParseDomainName(sr),
                            LdapParser.ParseGuid(sr),
                            0,
                            LdapParser.ParseCaCertificate(sr),
                            LdapParser.ParseSecurityDescriptor(sr)
                        );
                    }
                }
            }
        }

        public IEnumerable<CertificateTemplate> GetCertificateTemplates(List<string> user_sids = null)
        {
            var templates = new List<CertificateTemplate>();

            // Container location per MS-WCCE 2.2.2.11.1 Certificates Templates Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44

            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certificate Templates,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner, Filter = "(objectclass=pKICertificateTemplate)" })
                {
                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            templates.Add(new CertificateTemplate(
                                sr.Path,
                                LdapParser.ParseName(sr),
                                LdapParser.ParseDomainName(sr),
                                LdapParser.ParseGuid(sr),
                                LdapParser.ParseSchemaVersion(sr),
                                LdapParser.ParseDisplayName(sr),
                                LdapParser.ParsePkiExpirationPeriod(sr),
                                LdapParser.ParsePkiOverlapPeriod(sr),
                                LdapParser.ParsePkiCertTemplateOid(sr),
                                LdapParser.ParsePkiCertificateNameFlag(sr),
                                LdapParser.ParsePkiEnrollmentFlag(sr),
                                LdapParser.ParseExtendedKeyUsages(sr),
                                LdapParser.ParseAuthorizedSignatures(sr),
                                LdapParser.ParseRaApplicationPolicies(sr),
                                LdapParser.ParseRaIssuancePolicies(sr),
                                LdapParser.ParseSecurityDescriptor(sr),
                                LdapParser.ParseCertificateApplicationPolicies(sr),
                                LdapParser.ParseCertificateIssuancePolicies(sr)?.Select(o => GetEnterpriseOid(o)),
                                user_sids
                            ));
                        }

                        return templates;
                    }
                }
            }
        }

        public DirectoryEntry GetCertificateTemplateEntry(string template)
        {
            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certificate Templates,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { SecurityMasks = SecurityMasks.Dacl | SecurityMasks.Owner, Filter = $"(&(objectclass=pKICertificateTemplate)(name={template}))" })
                {
                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            return sr.GetDirectoryEntry();
                        }

                        return null;
                    }
                }
            }
        }

        public List<CertificateAuthority> GetRootCAs()
        {
            var cas = new List<CertificateAuthority>();

            // Container location per MS-WCCE 2.2.2.11.4 Certification Authorities Container
            // - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/6c446198-f670-4885-97a9-cbc50a2b96b4

            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=Certification Authorities,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { Filter = "(objectCategory=certificationAuthority)" })
                {
                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            cas.Add(new CertificateAuthority(
                                sr.Path,
                                LdapParser.ParseName(sr),
                                LdapParser.ParseDomainName(sr),
                                LdapParser.ParseGuid(sr),
                                0,
                                LdapParser.ParseCaCertificate(sr),
                                LdapParser.ParseSecurityDescriptor(sr)
                            ));
                        }

                        return cas;
                    }
                }
            }
        }

        public List<CertificateEnterpriseOid> GetEnterpriseOids()
        {
            var oids = new List<CertificateEnterpriseOid>();

            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=OID,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { Filter = "(objectClass=msPKI-Enterprise-Oid)" })
                {
                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            oids.Add(new CertificateEnterpriseOid(
                                sr.Path,
                                LdapParser.ParseName(sr),
                                LdapParser.ParseGuid(sr),
                                LdapParser.ParseDisplayName(sr),
                                LdapParser.ParsePkiCertTemplateOid(sr),
                                LdapParser.ParsePkiOidToGroupLink(sr),
                                LdapParser.ParseSecurityDescriptor(sr)));
                        }

                        return oids;
                    }
                }
            }
        }

        public CertificateEnterpriseOid GetEnterpriseOid(string oid)
        {
            using (var root = new DirectoryEntry($"LDAP://{LdapServer}CN=OID,CN=Public Key Services,CN=Services,{ConfigurationPath}"))
            {
                using (var ds = new DirectorySearcher(root) { Filter = $"(msPKI-Cert-Template-OID={oid})" })
                {
                    using (var results = ds.FindAll())
                    {
                        foreach (SearchResult sr in results)
                        {
                            return new CertificateEnterpriseOid(
                                sr.Path,
                                LdapParser.ParseName(sr),
                                LdapParser.ParseGuid(sr),
                                LdapParser.ParseDisplayName(sr),
                                LdapParser.ParsePkiCertTemplateOid(sr),
                                LdapParser.ParsePkiOidToGroupLink(sr),
                                LdapParser.ParseSecurityDescriptor(sr));
                        }

                        return null;
                    }
                }
            }
        }
    }
}
