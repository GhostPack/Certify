using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Certify.Lib
{
    class CertConverter
    {
        internal class RSAParameterTraits
        {
            /*
             * Reference : 
             *     https://www.codeproject.com/Articles/162194/Certificates-to-DB-and-Back
             */
            public RSAParameterTraits(int modulusLengthInBits)
            {
                int assumedLength = -1;
                double logbase = Math.Log(modulusLengthInBits, 2);
                if (logbase == (int)logbase)
                {
                    assumedLength = modulusLengthInBits;
                }
                else
                {
                    assumedLength = (int)(logbase + 1.0);
                    assumedLength = (int)(Math.Pow(2, assumedLength));
                    System.Diagnostics.Debug.Assert(false);
                }

                switch (assumedLength)
                {
                    case 1024:
                        this.size_Mod = 0x80;
                        this.size_Exp = -1;
                        this.size_D = 0x80;
                        this.size_P = 0x40;
                        this.size_Q = 0x40;
                        this.size_DP = 0x40;
                        this.size_DQ = 0x40;
                        this.size_InvQ = 0x40;
                        break;
                    case 2048:
                        this.size_Mod = 0x100;
                        this.size_Exp = -1;
                        this.size_D = 0x100;
                        this.size_P = 0x80;
                        this.size_Q = 0x80;
                        this.size_DP = 0x80;
                        this.size_DQ = 0x80;
                        this.size_InvQ = 0x80;
                        break;
                    case 4096:
                        this.size_Mod = 0x200;
                        this.size_Exp = -1;
                        this.size_D = 0x200;
                        this.size_P = 0x100;
                        this.size_Q = 0x100;
                        this.size_DP = 0x100;
                        this.size_DQ = 0x100;
                        this.size_InvQ = 0x100;
                        break;
                    default:
                        System.Diagnostics.Debug.Assert(false);
                        break;
                }
            }

            public int size_Mod = -1;
            public int size_Exp = -1;
            public int size_D = -1;
            public int size_P = -1;
            public int size_Q = -1;
            public int size_DP = -1;
            public int size_DQ = -1;
            public int size_InvQ = -1;
        }

        private static byte[] AlignBytes(byte[] inputBytes, int alignSize)
        {
            int inputBytesSize = inputBytes.Length;

            if ((alignSize != -1) && (inputBytesSize < alignSize))
            {
                byte[] buf = new byte[alignSize];

                for (int i = 0; i < inputBytesSize; ++i)
                {
                    buf[i + (alignSize - inputBytesSize)] = inputBytes[i];
                }

                return buf;
            }
            else
            {
                return inputBytes;
            }
        }

        private static RSACryptoServiceProvider DecodePrivateKey(byte[] privKey)
        {
            MemoryStream memoryStream = new MemoryStream(privKey);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            try
            {
                int storage = (int)binaryReader.ReadUInt16();

                if (storage == 0x8130)
                {
                    binaryReader.ReadByte();
                }
                else if (storage == 0x8230)
                {
                    binaryReader.ReadUInt16();
                }
                else
                {
                    throw new InvalidDataException("invalid data format");
                }

                storage = (int)binaryReader.ReadUInt16();

                if (storage != 0x0102)
                {
                    throw new InvalidDataException("invalid data format");
                }

                storage = (int)binaryReader.ReadByte();

                if (storage != 0)
                {
                    throw new InvalidDataException("invalid data format");
                }

                CspParameters cspParams = new CspParameters();
                cspParams.Flags = CspProviderFlags.NoFlags;
                cspParams.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
                cspParams.ProviderType = 0x18;

                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cspParams);
                RSAParameters rsaParams = new RSAParameters();
                rsaParams.Modulus = binaryReader.ReadBytes(DecodeSize(binaryReader));

                RSAParameterTraits traits = new RSAParameterTraits(rsaParams.Modulus.Length * 8);

                rsaParams.Modulus = AlignBytes(rsaParams.Modulus, traits.size_Mod);
                rsaParams.Exponent = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_Exp);
                rsaParams.D = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_D);
                rsaParams.P = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_P);
                rsaParams.Q = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_Q);
                rsaParams.DP = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_DP);
                rsaParams.DQ = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_DQ);
                rsaParams.InverseQ = AlignBytes(binaryReader.ReadBytes(DecodeSize(binaryReader)), traits.size_InvQ);

                rsa.ImportParameters(rsaParams);

                return rsa;
            }
            catch
            {
                return null;
            }
            finally
            {
                binaryReader.Close();
            }
        }

        private static int DecodeSize(BinaryReader binaryReader)
        {
            int count;
            int storage = (int)binaryReader.ReadByte();

            if (storage != 2)
            {
                throw new InvalidDataException("invalid data format");
            }

            storage = (int)binaryReader.ReadByte();

            if (storage == 0x81)
            {
                count = (int)binaryReader.ReadByte();
            }
            else if (storage == 0x82)
            {
                count = ((int)binaryReader.ReadByte()) << 8;
                count += (int)binaryReader.ReadByte();
            }
            else
            {
                count = storage;
            }

            while (binaryReader.ReadByte() == 0)
            {
                count--;
            }

            binaryReader.BaseStream.Seek(-1, System.IO.SeekOrigin.Current);

            return count;
        }

        private static byte[] GetPrivateKeyFromPemString(string pem)
        {
            MatchCollection matches;
            string base64Content;
            Regex regexPrivateKey = new Regex(
                @"-+BEGIN RSA PRIVATE KEY-+[a-zA-Z0-9\+=/\r\n]+-+END RSA PRIVATE KEY-+",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            matches = regexPrivateKey.Matches(pem);

            if (matches.Count == 0)
            {
                throw new InvalidOperationException("Failed to get private key");
            }

            base64Content = Regex.Replace(
                matches[0].ToString(),
                @"(-+[A-Z\s]+-+|\s+)",
                string.Empty);

            return Convert.FromBase64String(base64Content);
        }

        private static byte[] GetPublicKeyFromPemString(string pem)
        {
            MatchCollection matches;
            string base64Content;
            Regex regexCertificate = new Regex(
                @"-+BEGIN CERTIFICATE-+[a-zA-Z0-9\+/=\r\n]+-+END CERTIFICATE-+",
                RegexOptions.Compiled | RegexOptions.IgnoreCase);

            matches = regexCertificate.Matches(pem);

            if (matches.Count == 0)
            {
                throw new InvalidOperationException("Failed to get certificate");
            }

            base64Content = Regex.Replace(
                matches[0].ToString(),
                @"(-+[A-Z\s]+-+|\s+)",
                string.Empty);

            return Convert.FromBase64String(base64Content);
        }

        public static string GetPfxFromPemString(string privateKeyPemString, string certPemString, string password, bool nowrap)
        {
            RSACryptoServiceProvider privKey = DecodePrivateKey(GetPrivateKeyFromPemString(privateKeyPemString));
            X509Certificate2 cert = new X509Certificate2(GetPublicKeyFromPemString(certPemString));
            cert.PrivateKey = privKey;

            var encodedPfx = Convert.ToBase64String(cert.Export(X509ContentType.Pfx, password));
            var result = new StringBuilder();

            if (nowrap)
            {
                result.Append(encodedPfx);
            }
            else
            {
                for (var idx = 0; idx < encodedPfx.Length; idx++)
                {
                    result.Append(encodedPfx[idx]);
                    if ((idx + 1) % 64 == 0)
                    {
                        result.Append("\r\n");
                    }
                }
            }

            return result.ToString();
        }

        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }
    }
}
