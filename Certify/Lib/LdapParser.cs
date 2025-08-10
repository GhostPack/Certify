using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Certify.Domain;

namespace Certify.Lib
{
    internal class LdapParser
    {
        public static PkiCertificateAuthorityFlags ParsePkiCertificateAuthorityFlags(SearchResult sr)
        {
            if (sr.Properties.Contains("flags"))
            {
                if (Enum.TryParse(sr.Properties["flags"][0].ToString(), out PkiCertificateAuthorityFlags result))
                    return result;
            }

            return 0;
        }

        public static string ParseDnsHostname(SearchResult sr)
        {
            if (sr.Properties.Contains("dnshostname"))
                return sr.Properties["dnshostname"][0].ToString();
            else
                return null;
        }

        public static ActiveDirectorySecurity ParseSecurityDescriptor(SearchResult sr)
        {
            if (sr.Properties.Contains("ntsecuritydescriptor"))
            {
                var sd = new ActiveDirectorySecurity();
                sd.SetSecurityDescriptorBinaryForm((byte[])sr.Properties["ntsecuritydescriptor"][0]);
                return sd;
            }

            return null;
        }

        public static List<X509Certificate2> ParseCaCertificate(SearchResult sr)
        {
            if (sr.Properties.Contains("cacertificate"))
            {
                var certs = new List<X509Certificate2>();

                foreach (var cert_bytes in sr.Properties["cacertificate"])
                    certs.Add(new X509Certificate2((byte[])cert_bytes));

                return certs;
            }

            return null;
        }

        public static List<string> ParseCertificateTemplate(SearchResult sr)
        {
            if (sr.Properties.Contains("certificatetemplates"))
            {
                var templates = new List<string>();

                foreach (var template in sr.Properties["certificatetemplates"])
                    templates.Add($"{template}");

                return templates;
            }

            return null;
        }

        public static msPKICertificateNameFlag ParsePkiCertificateNameFlag(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-certificate-name-flag"))
            {
                return ParseIntToEnum<msPKICertificateNameFlag>(sr.Properties["mspki-certificate-name-flag"][0].ToString());
            }

            return 0;
        }

        public static msPKIEnrollmentFlag ParsePkiEnrollmentFlag(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-enrollment-flag"))
                return ParseUIntToEnum<msPKIEnrollmentFlag>(sr.Properties["mspki-enrollment-flag"][0].ToString());

            return 0;
        }

        public static string ParseDisplayName(SearchResult sr)
        {
            if (sr.Properties.Contains("displayname"))
                return sr.Properties["displayname"][0].ToString();

            return null;
        }

        public static string ParseName(SearchResult sr)
        {
            if (sr.Properties.Contains("name"))
                return sr.Properties["name"][0].ToString();

            return null;
        }

        public static string ParseSamAccountName(SearchResult sr)
        {
            if (sr.Properties.Contains("samaccountname"))
                return sr.Properties["samaccountname"][0].ToString();

            return null;
        }

        public static string ParseDomainName(SearchResult sr)
        {
            if (sr.Properties.Contains("distinguishedname"))
            {
                var dn = sr.Properties["distinguishedname"][0].ToString();
                var idx = dn.IndexOf("DC=");

                if (idx != -1)
                    return dn.Substring(idx + 3, dn.Length - idx - 3).Replace(",DC=", ".");
            }

            return null;
        }

        public static string ParseDistinguishedName(SearchResult sr)
        {
            if (sr.Properties.Contains("distinguishedname"))
                return sr.Properties["distinguishedname"][0].ToString();

            return null;
        }

        public static Guid ParseGuid(SearchResult sr)
        {
            if (sr.Properties.Contains("objectguid"))
                return new Guid((byte[])sr.Properties["objectguid"][0]);

            return Guid.Empty;
        }

        public static int ParseSchemaVersion(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-template-schema-version"))
            {
                if (int.TryParse(sr.Properties["mspki-template-schema-version"][0].ToString(), out int schema_version))
                    return schema_version;
            }

            return 0;
        }

        public static Oid ParsePkiCertTemplateOid(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-cert-template-oid"))
                return new Oid(sr.Properties["mspki-cert-template-oid"][0].ToString());

            return null;
        }

        public static string ParsePkiOidToGroupLink(SearchResult sr)
        {
            if (sr.Properties.Contains("msDS-OIDToGroupLink"))
                return sr.Properties["msDS-OIDToGroupLink"][0].ToString();

            return null;
        }

        public static string ParsePkiOverlapPeriod(SearchResult sr)
        {
            if (sr.Properties.Contains("pKIOverlapPeriod"))
                return ConvertPKIPeriod((byte[])sr.Properties["pKIOverlapPeriod"][0]);

            return null;
        }

        public static string ParsePkiExpirationPeriod(SearchResult sr)
        {
            if (sr.Properties.Contains("pKIExpirationPeriod"))
                return ConvertPKIPeriod((byte[])sr.Properties["pKIExpirationPeriod"][0]);

            return null;
        }

        public static IEnumerable<string> ParseExtendedKeyUsages(SearchResult sr)
        {
            if (sr.Properties.Contains("pkiextendedkeyusage"))
                return from object oid in sr.Properties["pkiextendedkeyusage"] select oid.ToString();

            return null;
        }

        public static int ParseAuthorizedSignatures(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-ra-signature"))
            {
                if (int.TryParse(sr.Properties["mspki-ra-signature"][0].ToString(), out int authorized_signatures))
                    return authorized_signatures;
            }

            return 0;
        }

        public static IEnumerable<string> ParseRaApplicationPolicies(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-ra-application-policies"))
                return from object oid in sr.Properties["mspki-ra-application-policies"] select oid.ToString();

            return null;
        }

        public static IEnumerable<string> ParseRaIssuancePolicies(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-ra-policies"))
                return from object oid in sr.Properties["mspki-ra-policies"] select oid.ToString();

            return null;
        }

        public static IEnumerable<string> ParseCertificateApplicationPolicies(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-certificate-application-policy"))
                return from object oid in sr.Properties["mspki-certificate-application-policy"] select oid.ToString();

            return null;
        }

        public static IEnumerable<string> ParseCertificateIssuancePolicies(SearchResult sr)
        {
            if (sr.Properties.Contains("mspki-certificate-policy"))
                return from object oid in sr.Properties["mspki-certificate-policy"] select oid.ToString();

            return null;
        }

        public static T ParseUIntToEnum<T>(string value)
        {
            return (T)Enum.Parse(typeof(T), Convert.ToUInt32(value).ToString());
        }

        public static T ParseIntToEnum<T>(string value)
        {
            return (T)Enum.Parse(typeof(T), unchecked((uint)Convert.ToInt32(value)).ToString());
        }

        public static string ConvertPKIPeriod(byte[] bytes)
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
