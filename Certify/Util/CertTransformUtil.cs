using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Linq;

#if !DISARMED

namespace Certify.Lib
{
    internal class CertTransformUtil
    {
        private static readonly SecureRandom Random = new SecureRandom();

        public static byte[] MakePfx(string certificate_pem, string private_key_pem)
        {
            X509Certificate certificate = null;

            using (var sr = new StringReader(certificate_pem))
            {
                var pr = new PemReader(sr);
                object temp = pr.ReadObject();

                if (temp != null && temp is X509Certificate)
                    certificate = (X509Certificate)temp;
            }

            AsymmetricCipherKeyPair keys = null;

            using (var sr = new StringReader(private_key_pem))
            {
                var pr = new PemReader(sr);
                object temp = pr.ReadObject();

                if (temp != null && temp is AsymmetricCipherKeyPair)
                    keys = (AsymmetricCipherKeyPair)temp;
            }

            return MakePfx(null, certificate, keys.Private);
        }

        public static byte[] MakePfx(string password, X509Certificate certificate, AsymmetricKeyParameter private_key)
        {
            var certificate_entry = new X509CertificateEntry(certificate);
            var friendly_name = certificate.SubjectDN.ToString();

            var store = new Pkcs12Store();
            store.SetCertificateEntry(friendly_name, certificate_entry);
            store.SetKeyEntry(friendly_name, new AsymmetricKeyEntry(private_key), new X509CertificateEntry[] { certificate_entry });

            using (var stream = new MemoryStream())
            {
                store.Save(stream, password?.ToArray(), Random);
                return stream.ToArray();
            }
        }

        public static Tuple<X509Certificate, AsymmetricKeyParameter> SplitPfx(byte[] pfx, string password)
        {
            using (var stream = new MemoryStream(pfx))
            {
                return SplitPfxFromStore(new Pkcs12Store(stream, password?.ToArray()));
            }
        }

        public static Tuple<X509Certificate, AsymmetricKeyParameter> SplitPfx(string path, string password)
        {
            using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                return SplitPfxFromStore(new Pkcs12Store(stream, password?.ToArray()));
            }
        }

        private static Tuple<X509Certificate, AsymmetricKeyParameter> SplitPfxFromStore(Pkcs12Store store)
        {
            if (store.Count > 1)
                throw new ArgumentException("The PFX store contains more than 1 key");
            else
            {
                foreach (var e in store.Aliases)
                {
                    var cert = store.GetCertificate(e.ToString());
                    var key = store.GetKey(e.ToString());

                    return new Tuple<X509Certificate, AsymmetricKeyParameter>(cert.Certificate, key.Key);
                }

                throw new ArgumentException("The PFX store does not contain any keys");
            }
        }

        public static Tuple<string, string> MakePem(byte[] pfx, string password)
        {
            string make_pem(object o)
            {
                if (o == null)
                    return string.Empty;
                else
                {
                    using (var sw = new StringWriter())
                    {
                        var pw = new PemWriter(sw);
                        pw.WriteObject(o);

                        sw.Flush();
                        return sw.ToString();
                    }
                }
            }

            var key_pair = SplitPfx(pfx, password);

            var cert_pem = make_pem(key_pair.Item1);
            var private_key_pem = make_pem(key_pair.Item2);

            return new Tuple<string, string>(cert_pem, private_key_pem);
        }

        public static byte[] RemovePfxPassword(byte[] pfx, string password)
        {
            var store = new Pkcs12Store();

            using (var stream = new MemoryStream(pfx))
                store.Load(stream, password?.ToArray());

            using (var stream = new MemoryStream())
            {
                store.Save(stream, null, Random);
                return stream.ToArray();
            }
        }

        public static string GetPfxIdentifier(byte[] pfx, string password)
        {
            var store = new Pkcs12Store();

            using (var stream = new MemoryStream(pfx))
                store.Load(stream, password?.ToArray());

            foreach (string alias in store.Aliases)
                return alias;

            return "<unknown>";
        }
    }
}

#endif