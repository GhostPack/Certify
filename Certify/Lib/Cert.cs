using System;
using System.DirectoryServices.AccountManagement;
using CERTENROLLLib;
using CERTCLILib;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using Certify.Lib;

namespace Certify
{
    class Cert
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

        class CertificateRequest
        {
            public CertificateRequest(string request, string privateKeyPem)
            {
                Request = request;
                PrivateKeyPem = privateKeyPem;
            }

            public string Request { get; set; }
            public string PrivateKeyPem { get; set; }

        }

        // create a certificate request message from a given enterprise template name
        private static CertificateRequest CreateCertRequestMessage(string templateName, bool machineContext = false, string subjectName = "", string altName = "", string url = "", string sidExtension = "")
        {
            if (String.IsNullOrEmpty(subjectName))
            {
                if (machineContext)
                {
                    subjectName = GetCurrentComputerDN();
                    Console.WriteLine($"[*] No subject name specified, using current machine as subject");
                }
                else
                {
                    if (WindowsIdentity.GetCurrent().IsSystem)
                    {
                        Console.WriteLine($"\n[!] WARNING: You are currently running as SYSTEM. You may want to use the /machine argument to use the machine account instead.");
                    }

                    subjectName = GetCurrentUserDN();
                    Console.WriteLine($"[*] No subject name specified, using current context as subject.");
                }
            }

            Console.WriteLine($"\r\n[*] Template                : {templateName}");
            Console.WriteLine($"[*] Subject                 : {subjectName}");
            if (!String.IsNullOrEmpty(altName))
            {
                Console.WriteLine($"[*] AltName                 : {altName}");
            }
            if (!String.IsNullOrEmpty(url))
            {
                Console.WriteLine($"[*] URL                     : {url}");
            }
            if (!String.IsNullOrEmpty(sidExtension))
            {
                Console.WriteLine($"[*] SidExtension            : {sidExtension}");
            }

            var privateKey = CreatePrivateKey(machineContext);

            // export the private key and transform it into a .pem
            var privateKeyBase64 = privateKey.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64);
            var privateKeyPEM = ConvertToPEM(privateKeyBase64);

            // construct the request for the template name specified
            var objPkcs10 = new CX509CertificateRequestPkcs10();
            var context = machineContext
                ? X509CertificateEnrollmentContext.ContextMachine
                : X509CertificateEnrollmentContext.ContextUser;

            objPkcs10.InitializeFromPrivateKey(context, privateKey, templateName);

            var objDN = new CX500DistinguishedName();

            try
            {
                objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_NONE);
            }
            catch
            {
                // case when commas are present in the DN
                objDN.Encode(subjectName, X500NameFlags.XCN_CERT_NAME_STR_SEMICOLON_FLAG);
            }

            objPkcs10.Subject = objDN;

            if (!String.IsNullOrEmpty(altName))
            {
                // ref- https://gist.github.com/jimmyca15/8f737f5f0bcf347450bd6d6bf34f4f7e#file-certificate-cs-L86-L101

                // format 1 - required for the CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT scenario
                var names = new CAlternativeNamesClass();
                var altnames = new CX509ExtensionAlternativeNamesClass();
                var name = new CAlternativeNameClass();

                // Add the UPN (Principal Name) to the SAN extension
                name.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME, altName);
                names.Add(name);

                // Add the URL to the SAN extension as a separate entry
                if (!string.IsNullOrEmpty(url))
                {
                    var nameUrl = new CAlternativeNameClass();
                    nameUrl.InitializeFromString(AlternativeNameType.XCN_CERT_ALT_NAME_URL, url);
                    names.Add(nameUrl);
                }

                // format 2 - required for the EDITF_ATTRIBUTESUBJECTALTNAME2 scenario
                altnames.InitializeEncode(names);
                objPkcs10.X509Extensions.Add((CX509Extension)altnames);

                var altNamePair = new CX509NameValuePair();
                if (!string.IsNullOrEmpty(url))
                {
                    altNamePair.Initialize("SAN", $"upn={altName}&URL={url}");
                }
                else {
                    altNamePair.Initialize("SAN", $"upn={altName}");
                }
                objPkcs10.NameValuePairs.Add(altNamePair);

                // SID extension
                if(!String.IsNullOrEmpty(sidExtension)) {
                    var extBytes = Certify.Lib.CertSidExtension.EncodeSidExtension(new SecurityIdentifier(sidExtension));
                    var oid = new CObjectId();
                    oid.InitializeFromValue("1.3.6.1.4.1.311.25.2");
                    var sidExt = new CX509Extension();
                    sidExt.Initialize(oid, EncodingType.XCN_CRYPT_STRING_BASE64, Convert.ToBase64String(extBytes));
                    objPkcs10.X509Extensions.Add(sidExt);
                }
            }

            var objEnroll = new CX509Enrollment();
            objEnroll.InitializeFromRequest(objPkcs10);
            var base64request = objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return new CertificateRequest(base64request, privateKeyPEM);
        }

        private static IX509PrivateKey CreatePrivateKey(bool machineContext)
        {
            var cspInfo = new CCspInformations();
            cspInfo.AddAvailableCsps();

            var privateKey = new CX509PrivateKey
            {
                Length = 2048,
                KeySpec = X509KeySpec.XCN_AT_SIGNATURE,
                KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES,
                MachineContext = machineContext,
                ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG,
                CspInformations = cspInfo
            };
            privateKey.Create();

            return privateKey;
        }


        // create a certificate request message from a given enterprise template name on behalf of another user
        private static CertificateRequest CreateCertRequestOnBehalfMessage(string templateName, string onBehalfUser, string signerCertPath, string signerCertPassword, bool machineContext = false)
        {
            if (String.IsNullOrEmpty(signerCertPath))
                throw new Exception("signerCertPath is empty");

            if (!File.Exists(signerCertPath))
                throw new Exception($"signerCertPath '{signerCertPath}' doesn't exist!");

            Console.WriteLine($"\r\n[*] Template                : {templateName}");
            Console.WriteLine($"[*] On Behalf Of            : {onBehalfUser}");

            X509Certificate2? cert = null;

            var privateKey = CreatePrivateKey(machineContext);

            // export the private key and transform it into a .pem
            var privateKeyBase64 = privateKey.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64);
            var privateKeyPEM = ConvertToPEM(privateKeyBase64);

            // construct the request for the template name specified
            var objPkcs10 = new CX509CertificateRequestPkcs10();
            var context = machineContext
                ? X509CertificateEnrollmentContext.ContextMachine
                : X509CertificateEnrollmentContext.ContextUser;

            objPkcs10.InitializeFromPrivateKey(context, privateKey, templateName);
            objPkcs10.Encode();

            var pkcs7 = new CX509CertificateRequestPkcs7();
            pkcs7.InitializeFromInnerRequest(objPkcs10);
            pkcs7.RequesterName = onBehalfUser;

            var signer = new CSignerCertificate();

            string base64request;
            try
            {
                cert = new X509Certificate2(signerCertPath, signerCertPassword);

                // temporarily add this cert to the local user store so we can sign the request
                var store = new X509Store(StoreName.My);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert);

                signer.Initialize(false, X509PrivateKeyVerify.VerifyNone, EncodingType.XCN_CRYPT_STRING_HEXRAW, cert.Thumbprint);

                pkcs7.SignerCertificate = signer;

                var objEnroll = new CX509Enrollment();
                objEnroll.InitializeFromRequest(pkcs7);
                base64request = objEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

                // now remove the temp cert
                store.Remove(cert);
            }
            finally
            {
                if (cert != null)
                {
                    // This method can be used to reset the state of the certificate. It also frees any resources associated with the certificate.
                    cert.Reset();
                    cert = null;
                }
            }

            return new CertificateRequest(base64request, privateKeyPEM);
        }


        // Given a certificate authority (CA) and a certificate request message,
        //      actually send the request to the CA
        //      CA format example: @"dc.theshire.local\theshire-DC-CA"
        public static int SendCertificateRequest(string CA, string message)
        {
            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.Submit(
                    CR_IN_BASE64 | CR_IN_FORMATANY,
                    message,
                    string.Empty,
                    CA);

            switch (iDisposition)
            {
                case CR_DISP_ISSUED:
                    Console.WriteLine("\r\n[*] CA Response             : The certificate had been issued.");
                    break;
                case CR_DISP_UNDER_SUBMISSION:
                    Console.WriteLine("\r\n[*] CA Response             : The certificate is still pending.");
                    break;
                default:
                    Console.WriteLine("\r\n[!] CA Response             : The submission failed: {0}", objCertRequest.GetDispositionMessage());
                    Console.WriteLine("[!] Last status             : 0x{0:X}", (uint)objCertRequest.GetLastStatus());
                    break;
            }
            return objCertRequest.GetRequestId();
        }


        // download the requested cert ID from the CA
        public static string DownloadCert(string CA, int requestId)
        {
            TextWriter s = new StringWriter();

            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.RetrievePending(requestId, CA);

            if (iDisposition == CR_DISP_ISSUED)
            {
                var cert = objCertRequest.GetCertificate(CR_OUT_BASE64);

                s.WriteLine("-----BEGIN CERTIFICATE-----");
                s.Write(cert);
                s.WriteLine("-----END CERTIFICATE-----");
            }
            else
            {
                throw new Exception($"Cert not yet issued yet! (iDisposition: {iDisposition})");
            }

            return s.ToString();
        }


        // download the requested cert ID from the CA and install it for the specified context (user/machine)
        public static string DownloadAndInstallCert(string CA, int requestId, X509CertificateEnrollmentContext context)
        {
            TextWriter outputStream = new StringWriter();

            var objCertRequest = new CCertRequest();
            var iDisposition = objCertRequest.RetrievePending(requestId, CA);

            if (iDisposition != CR_DISP_ISSUED)
                throw new Exception($"[X] Cert not yet issued! (iDisposition: {iDisposition})");
            
            var cert = objCertRequest.GetCertificate(CR_OUT_BASE64);

            outputStream.WriteLine("-----BEGIN CERTIFICATE-----");
            outputStream.Write(cert);
            outputStream.WriteLine("-----END CERTIFICATE-----");

            var objEnroll = new CX509Enrollment();
            objEnroll.Initialize(context);
            objEnroll.InstallResponse(
                InstallResponseRestrictionFlags.AllowUntrustedRoot,
                cert,
                EncodingType.XCN_CRYPT_STRING_BASE64,
                null);
            Console.WriteLine("[*] Certificates installed!");

            return outputStream.ToString();
        }


        // request a user/machine certificate
        public static void RequestCert(string CA, bool machineContext = false, string templateName = "User", string subject = "", string altName = "", string url = "", string sidExtension = "", bool install = false)
        {
            if (machineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("[*] Elevating to SYSTEM context for machine cert request");
                Elevator.GetSystem(() => RequestCert(CA, machineContext, templateName, subject, altName, url, sidExtension, install));
                return;
            }

            var userName = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine($"\r\n[*] Current user context    : {userName}");

            var csr = CreateCertRequestMessage(templateName, machineContext, subject, altName, url, sidExtension);


            Console.WriteLine($"\r\n[*] Certificate Authority   : {CA}");

            // send the request to the CA

            int requestID;
            try
            {
                requestID = SendCertificateRequest(CA, csr.Request);

                Console.WriteLine($"[*] Request ID              : {requestID}");

                Thread.Sleep(3000);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error sending the certificate request: {e}");
                return;
            }

            Console.WriteLine($"\r\n[*] cert.pem         :\r\n");
            Console.Write(csr.PrivateKeyPem);

            // download the certificate from the CA
            try
            {
                var certPemString = install
                    ? DownloadAndInstallCert(CA, requestID, X509CertificateEnrollmentContext.ContextUser)
                    : DownloadCert(CA, requestID);

                Console.WriteLine(certPemString);
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[X] Error downloading certificate: " + e.Message);
            }

            Console.WriteLine(
                    "\r\n[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out cert.pfx\r\n");
        }


        // request a certificate on behalf of another user
        public static void RequestCertOnBehalf(string CA, string templateName, string onBehalfUser, string signerCertPath, string signerCertPassword, bool machineContext = false)
        {
            if (machineContext && !WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("[*] Elevating to SYSTEM context for machine cert request");
                Elevator.GetSystem(() => RequestCertOnBehalf(CA, templateName, onBehalfUser, signerCertPath, signerCertPassword, machineContext));
                return;
            }

            var userName = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine($"\r\n[*] Current user context    : {userName}");

            var csr = CreateCertRequestOnBehalfMessage(templateName, onBehalfUser, signerCertPath, signerCertPassword, machineContext);

            Console.WriteLine($"\r\n[*] Certificate Authority   : {CA}");

            // send the request to the CA
            int requestID;
            try
            {
                requestID = SendCertificateRequest(CA, csr.Request);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error sending the certificate request: {e}");
                return;
            }


            Console.WriteLine($"[*] Request ID              : {requestID}");

            Thread.Sleep(3000);

            // download the certificate from the CA
            try
            {
                var certPemString = DownloadCert(CA, requestID);

                // if successful, display everything
                Console.WriteLine($"\r\n[*] cert.pem         :\r\n");
                Console.Write(csr.PrivateKeyPem);
                Console.WriteLine(certPemString);
                Console.WriteLine(
                    "\r\n[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out cert.pfx\r\n");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error downloading certificate: " + e);
            }

        }

        // takes the output of CX509PrivateKey.Export() , builds a RSA key,
        //    and converts that to a usable .pem
        public static string ConvertToPEM(string privKeyStr)
        {
            var rsa = new RSACryptoServiceProvider();
            var CryptoKey = Convert.FromBase64String(privKeyStr);
            rsa.ImportCspBlob(CryptoKey);

            return ExportPrivateKey(rsa);
        }

        // from https://stackoverflow.com/a/23739932
        //    internal helper used to convert a RSA key to a PEM string
        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            TextWriter outputStream = new StringWriter();

            var parameters = csp.ExportParameters(true);

            using var stream = new MemoryStream();
            var writer = new BinaryWriter(stream);
            writer.Write((byte)0x30); // SEQUENCE
            using (var innerStream = new MemoryStream())
            {
                var innerWriter = new BinaryWriter(innerStream);
                EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                EncodeIntegerBigEndian(innerWriter, parameters.D);
                EncodeIntegerBigEndian(innerWriter, parameters.P);
                EncodeIntegerBigEndian(innerWriter, parameters.Q);
                EncodeIntegerBigEndian(innerWriter, parameters.DP);
                EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                var length = (int)innerStream.Length;
                EncodeLength(writer, length);
                writer.Write(innerStream.GetBuffer(), 0, length);
            }

            var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
            outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");
            
            // Output as Base64 with lines chopped at 64 characters
            for (var i = 0; i < base64.Length; i += 64)
            {
                outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
            }
            outputStream.WriteLine("-----END RSA PRIVATE KEY-----");

            return outputStream.ToString();
        }

        // from https://stackoverflow.com/a/23739932
        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        // from https://stackoverflow.com/a/23739932
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        // gets the current distinguished name of the current user context
        private static string GetCurrentUserDN()
        {
            return UserPrincipal.Current.DistinguishedName.Replace(",", ", ");
        }


        // gets the current distinguished name of the current computer
        private static string GetCurrentComputerDN()
        {
            return $"CN={System.Net.Dns.GetHostEntry("").HostName}";
        }
    }
}