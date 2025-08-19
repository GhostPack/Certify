using System;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Cryptography;
using Certify.Lib;
using CERTENROLLLib;
using CERTCLILib;
using System.Collections.Generic;
using System.Linq;
using Certify.Domain;

#if !DISARMED

namespace Certify
{
    public enum SubjectAltNameType
    {
        None = 0,
        Upn,
        Dns,
        Email,
        Url
    }

    class CertEnrollment
    {
        // adapted from http://geekswithblogs.net/shaunxu/archive/2012/01/13/working-with-active-directory-certificate-service-via-c.aspx
        //
        // default certificate templates:
        //      https://forsenergy.com/en-us/certtmpl/html/e6868771-654b-44fd-9853-7cbdd9174f47.htm

        private const int CC_DEFAULTCONFIG = 0;
        private const int CC_UIPICKCONFIG = 0x1;
        private const int CR_IN_BASE64 = 0x1;
        private const int CR_IN_FORMATANY = 0;
        private const int CR_IN_PKCS10 = 0x100;
        private const int CR_DISP_ISSUED = 0x3;
        private const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private const int CR_OUT_BASE64 = 0x1;
        private const int CR_OUT_CHAIN = 0x100;

        // create a certificate request message from a given enterprise template name
        public static Tuple<string, string> CreateCertRequestMessage(string template_name, string subject_name, IEnumerable<Tuple<SubjectAltNameType, string>> subject_alt_names, 
            string sid_extension, IEnumerable<string> application_policies, int key_size, bool machine_context)
        {
            var private_key = CreatePrivateKey(machine_context, key_size);
            var private_key_pem = ConvertToPEM(private_key.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64));

            // construct the request for the template name specified
            var pkcs10 = (IX509CertificateRequestPkcs10V3)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            if (machine_context)
                pkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, private_key, string.Empty);
            else
                pkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser, private_key, string.Empty);

            pkcs10.X509Extensions.Add(CreateTemplateNameExtension(template_name));

            var distinguished_name = new CX500DistinguishedName();

            try
            {
                distinguished_name.Encode(subject_name, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            }
            catch // case when commas are present in the DN
            {
                distinguished_name.Encode(subject_name, X500NameFlags.XCN_CERT_NAME_STR_SEMICOLON_FLAG);
            }

            pkcs10.Subject = distinguished_name;

            if (subject_alt_names != null && subject_alt_names.Any())
            {
                pkcs10.X509Extensions.Add(CreateSanExtension(subject_alt_names)); // san format 1 - required for the ENROLLEE_SUPPLIES_SUBJECT scenario
                pkcs10.NameValuePairs.Add(CreateSanAttribute(subject_alt_names)); // san format 2 - required for the EDITF_ATTRIBUTESUBJECTALTNAME2 scenario
            }

            if (!string.IsNullOrEmpty(sid_extension))
                pkcs10.X509Extensions.Add(CreateSidExtension(sid_extension));

            if (application_policies != null && application_policies.Any())
                pkcs10.X509Extensions.Add(CreateApplicationPolicyExtension(application_policies));

            var cert_enrollment = new CX509Enrollment();
            cert_enrollment.InitializeFromRequest(pkcs10);
            var request_base64 = cert_enrollment.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return new Tuple<string, string>(request_base64, private_key_pem);
        }

        // create a certificate request message from a given enterprise template name on behalf of another user
        public static Tuple<string, string> CreateCertRequestOnBehalfMessage(string template_name, string on_behalf_user, byte[] signer_cert, string signer_cert_password,
            List<string> application_policies, int key_size, bool machine_context = false)
        {
            var private_key = CreatePrivateKey(machine_context, key_size);
            var private_key_pem = ConvertToPEM(private_key.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64));

            // construct the request for the template name specified
            var pkcs10 = (IX509CertificateRequestPkcs10V3)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509CertificateRequestPkcs10"));

            if (machine_context)
                pkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, private_key, string.Empty);
            else
                pkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser, private_key, string.Empty);

            pkcs10.X509Extensions.Add(CreateTemplateNameExtension(template_name));

            if (application_policies != null && application_policies.Any())
                pkcs10.X509Extensions.Add(CreateApplicationPolicyExtension(application_policies));

            pkcs10.Encode();

            var pkcs7 = new CX509CertificateRequestPkcs7();
            pkcs7.InitializeFromInnerRequest(pkcs10);
            pkcs7.RequesterName = on_behalf_user;

            using (X509Certificate2 cert = new X509Certificate2(signer_cert, signer_cert_password))
            {
                var store = new X509Store(StoreName.My);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert); // temporarily add this cert to the local user store so we can sign the request

                var signer = new CSignerCertificate();
                signer.Initialize(false, X509PrivateKeyVerify.VerifyNone, EncodingType.XCN_CRYPT_STRING_HEXRAW, cert.Thumbprint);
                pkcs7.SignerCertificate = signer;

                var cert_enrollment = new CX509Enrollment();
                cert_enrollment.InitializeFromRequest(pkcs7);
                var request_base64 = cert_enrollment.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

                store.Remove(cert); // now remove the temp cert
                return new Tuple<string, string>(request_base64, private_key_pem);
            }
        }

        public static string CreateCertRenewMessage(X509Certificate2 certificate, bool machine_context)
        {
            var pkcs7 = new CX509CertificateRequestPkcs7();

            var store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certificate); // temporarily add this cert to the local user store so we can initialize the request

            if (machine_context)
                pkcs7.InitializeFromCertificate(X509CertificateEnrollmentContext.ContextMachine, true, Convert.ToBase64String(certificate.RawData), 
                    EncodingType.XCN_CRYPT_STRING_BASE64, (X509RequestInheritOptions)0x7E0 /* Inherit All Flags */ | X509RequestInheritOptions.InheritPrivateKey);
            else
                pkcs7.InitializeFromCertificate(X509CertificateEnrollmentContext.ContextUser, true, Convert.ToBase64String(certificate.RawData), 
                    EncodingType.XCN_CRYPT_STRING_BASE64, (X509RequestInheritOptions)0x7E0 /* Inherit All Flags */  | X509RequestInheritOptions.InheritPrivateKey);

            var cert_enrollment = new CX509Enrollment();
            cert_enrollment.InitializeFromRequest(pkcs7);
            var request_base64 = cert_enrollment.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            store.Remove(certificate);
            return request_base64;
        }

        public static int SendCertificateRequest(string ca, string message)
        {
            var cert_request = new CCertRequest();
            var disposition = cert_request.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, message, string.Empty, ca);

            switch (disposition)
            {
                case CR_DISP_ISSUED:
                    Console.WriteLine("[*] CA Response             : The certificate has been issued.");
                    break;

                case CR_DISP_UNDER_SUBMISSION:
                    Console.WriteLine("[*] CA Response             : The certificate is still pending.");
                    break;

                default:
                    Console.WriteLine("[!] CA Response             : The submission failed: {0}", cert_request.GetDispositionMessage());
                    Console.WriteLine("[!] Last status             : 0x{0:X}", (uint)cert_request.GetLastStatus());
                    break;
            }

            return cert_request.GetRequestId();
        }

        public static string DownloadCert(string ca, int request_id)
        {
            using (TextWriter output_stream = new StringWriter())
            {
                var cert_request = new CCertRequest();
                var disposition = cert_request.RetrievePending(request_id, ca);

                if (disposition != CR_DISP_ISSUED)
                    throw new Exception($"certificate has not yet been issued! (disposition: {disposition})");

                var cert = cert_request.GetCertificate(CR_OUT_BASE64);

                output_stream.WriteLine("-----BEGIN CERTIFICATE-----");
                output_stream.Write(cert);
                output_stream.WriteLine("-----END CERTIFICATE-----");

                return output_stream.ToString();
            }
        }

        public static string DownloadAndInstallCert(string ca, int request_id, X509CertificateEnrollmentContext context)
        {
            using (TextWriter output_stream = new StringWriter())
            {
                var cert_request = new CCertRequest();
                var disposition = cert_request.RetrievePending(request_id, ca);

                if (disposition != CR_DISP_ISSUED)
                    throw new Exception($"certificate has not yet been issued! (disposition: {disposition})");

                var cert = cert_request.GetCertificate(CR_OUT_BASE64);

                output_stream.WriteLine("-----BEGIN CERTIFICATE-----");
                output_stream.Write(cert);
                output_stream.WriteLine("-----END CERTIFICATE-----");

                var cert_enrollment = new CX509Enrollment();
                cert_enrollment.Initialize(context);
                cert_enrollment.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedRoot, cert, EncodingType.XCN_CRYPT_STRING_BASE64, null);
                Console.WriteLine("[*] Certificate installed!");

                return output_stream.ToString();
            }
        }

        private static IX509PrivateKey CreatePrivateKey(bool machine_context, int key_size)
        {
            var csp_info = new CCspInformations();
            csp_info.AddAvailableCsps();

            var private_key = (IX509PrivateKey)Activator.CreateInstance(Type.GetTypeFromProgID("X509Enrollment.CX509PrivateKey"));
            private_key.Length = key_size;
            private_key.KeySpec = X509KeySpec.XCN_AT_SIGNATURE;
            private_key.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            private_key.MachineContext = machine_context;
            private_key.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            private_key.CspInformations = csp_info;
            private_key.Create();

            return private_key;
        }

        public static string ConvertToPEM(string private_key)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(private_key));
                return ExportPrivateKey(rsa);
            }
        }

        private static CX509NameValuePair CreateSanAttribute(IEnumerable<Tuple<SubjectAltNameType, string>> sans)
        {
            var kv_mapping = new Dictionary<SubjectAltNameType, string>()
            {
                { SubjectAltNameType.Upn, "upn" },
                { SubjectAltNameType.Dns, "Dns" },
                { SubjectAltNameType.Email, "Email" },
                { SubjectAltNameType.Url, "URL" }
            };

            var altname_pair = new CX509NameValuePair();
            altname_pair.Initialize("SAN", string.Join("&", sans.Select(x => $"{kv_mapping[x.Item1]}={x.Item2}")));

            return altname_pair;
        }

        private static CX509Extension CreateTemplateNameExtension(string template_name)
        {
            var template_extension = new CX509ExtensionTemplateName();
            template_extension.InitializeEncode(template_name);
            return (CX509Extension)template_extension;
        }

        private static CX509Extension CreateSanExtension(IEnumerable<Tuple<SubjectAltNameType, string>> sans)
        {
            var altname_mapping = new Dictionary<SubjectAltNameType, AlternativeNameType>()
            {
                { SubjectAltNameType.Upn, AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME },
                { SubjectAltNameType.Dns, AlternativeNameType.XCN_CERT_ALT_NAME_DNS_NAME },
                { SubjectAltNameType.Email, AlternativeNameType.XCN_CERT_ALT_NAME_RFC822_NAME },
                { SubjectAltNameType.Url, AlternativeNameType.XCN_CERT_ALT_NAME_URL }
            };

            // ref- https://gist.github.com/jimmyca15/8f737f5f0bcf347450bd6d6bf34f4f7e#file-certificate-cs-L86-L101
            var altnames = new CAlternativeNamesClass();

            foreach (var san in sans)
            {
                var altname = new CAlternativeNameClass();
                altname.InitializeFromString(altname_mapping[san.Item1], san.Item2);
                altnames.Add(altname);
            }

            var extension_altnames = new CX509ExtensionAlternativeNamesClass();
            extension_altnames.InitializeEncode(altnames);

            return (CX509Extension)extension_altnames;
        }

        private static CX509Extension CreateSidExtension(string sid)
        {
            var oid = new CObjectId();
            oid.InitializeFromValue(CommonOids.NtdsCaSecurityExt);

            var extension_sid = new CX509Extension();

            extension_sid.Initialize(oid, EncodingType.XCN_CRYPT_STRING_BASE64, 
                Convert.ToBase64String(CertSidExtension.EncodeSidExtension(sid)));

            return extension_sid;
        }

        public static byte[] CreateApplicationPolicyExtensionRaw(IEnumerable<string> oids)
        {
            return Convert.FromBase64String(CreateApplicationPolicyExtension(oids).RawData[EncodingType.XCN_CRYPT_STRING_BASE64]);
        }

        private static CX509Extension CreateApplicationPolicyExtension(IEnumerable<string> oids)
        {
            var policies = CreatePolicies(oids);

            var x509_application_policies = new CX509ExtensionMSApplicationPoliciesClass();
            x509_application_policies.InitializeEncode(policies);

            return (CX509Extension)x509_application_policies;
        }

        public static byte[] CreateIssuancePolicyExtensionRaw(IEnumerable<string> oids)
        {
            return Convert.FromBase64String(CreateIssuancePolicyExtension(oids).RawData[EncodingType.XCN_CRYPT_STRING_BASE64]);
        }

        private static CX509Extension CreateIssuancePolicyExtension(IEnumerable<string> oids)
        {
            var policies = CreatePolicies(oids);

            var x509_issuance_policies = new CX509ExtensionCertificatePoliciesClass();
            x509_issuance_policies.InitializeEncode(policies);

            return (CX509Extension)x509_issuance_policies;
        }

        private static CCertificatePoliciesClass CreatePolicies(IEnumerable<string> oids)
        {
            var policies = new CCertificatePoliciesClass();

            foreach (var oid in oids)
            {
                var policy_oid = new CObjectIdClass();
                policy_oid.InitializeFromValue(oid);

                var policy = new CCertificatePolicyClass();
                policy.Initialize(policy_oid);

                policies.Add(policy);
            }

            return policies;
        }

        // from https://stackoverflow.com/a/23739932
        //    internal helper used to convert a RSA key to a PEM string
        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly)
                throw new ArgumentException("CSP does not contain a private key", "csp");

            using (var output_stream = new StringWriter())
            {
                var parameters = csp.ExportParameters(true);

                using (var stream = new MemoryStream())
                {
                    using (var writer = new BinaryWriter(stream))
                    {
                        writer.Write((byte)0x30); // SEQUENCE

                        using (var inner_stream = new MemoryStream())
                        {
                            using (var inner_writer = new BinaryWriter(inner_stream))
                            {
                                EncodeIntegerBigEndian(inner_writer, new byte[] { 0x00 }); // Version
                                EncodeIntegerBigEndian(inner_writer, parameters.Modulus);
                                EncodeIntegerBigEndian(inner_writer, parameters.Exponent);
                                EncodeIntegerBigEndian(inner_writer, parameters.D);
                                EncodeIntegerBigEndian(inner_writer, parameters.P);
                                EncodeIntegerBigEndian(inner_writer, parameters.Q);
                                EncodeIntegerBigEndian(inner_writer, parameters.DP);
                                EncodeIntegerBigEndian(inner_writer, parameters.DQ);
                                EncodeIntegerBigEndian(inner_writer, parameters.InverseQ);

                                EncodeLength(writer, (int)inner_stream.Length);
                                inner_stream.WriteTo(stream); //writer.Write(inner_stream.GetBuffer(), 0, (int)inner_stream.Length);
                            }
                        }

                        var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                        output_stream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");

                        // Output as Base64 with lines chopped at 64 characters
                        for (var i = 0; i < base64.Length; i += 64)
                            output_stream.WriteLine(base64, i, Math.Min(64, base64.Length - i));

                        output_stream.WriteLine("-----END RSA PRIVATE KEY-----");
                        return output_stream.ToString();
                    }
                }
            }
        }

        // from https://stackoverflow.com/a/23739932
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            else if (length < 0x80)
                stream.Write((byte)length);
            else
            {
                int bytes_required = 0;

                for (var i = length; i > 0; i >>= 8)
                    bytes_required++;

                stream.Write((byte)(bytes_required | 0x80));

                for (var i = bytes_required - 1; i >= 0; i--)
                    stream.Write((byte)(length >> (8 * i) & 0xff));
            }
        }

        // from https://stackoverflow.com/a/23739932
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool force_unsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER

            var prefix_zeros = 0;

            for (var i = 0; i < value.Length && value[i] == 0; i++)
                prefix_zeros++;

            if (value.Length - prefix_zeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (force_unsigned && value[prefix_zeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefix_zeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefix_zeros);
                }

                for (var i = prefix_zeros; i < value.Length; i++)
                    stream.Write(value[i]);
            }
        }
    }
}

#endif