using System;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Certify.Domain;

#if !DISARMED

namespace Certify.Lib
{
    [StructLayout(LayoutKind.Sequential)]
    public struct CERTTRANSBLOB
    {
        public int cb;
        public IntPtr pb;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CAINFO
    {
        public uint cbSize;
        public int CAType;
        public uint cCASignatureCerts;
        public uint cCAExchangeCerts;
        public uint cExitAlgorithms;
        public int lPropIDMax;
        public int lRoleSeparationEnabled;
        public uint cKRACertUsedCount;
        public uint cKRACertCount;
        public uint fAdvancedServer;
    }

    [ComImport]
    [Guid("7fe0d935-dda6-443f-85d0-1cfb58fe41dd")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface ICertAdminD2
    {
        // ICertAdminD (opnum 3 - 30) : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/46496f1f-a631-42b3-a60e-33f95fb6fed1

        [PreserveSig] // Opnum 3
        int SetExtension(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            uint dwRequestId,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszExtensionName,
            uint dwType,
            uint dwFlags,
            CERTTRANSBLOB pctbValue);

        [PreserveSig] // Opnum 4
        int SetAttributes(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            uint dwRequestId,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAttributes);

        [PreserveSig] // Opnum 5
        int ResubmitRequest(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            uint dwRequestId,
            out uint pdwDisposition);

        [PreserveSig] // Opnum 6
        int DenyRequest(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            uint dwRequestId);

        void Proc7(); // IsValidCertificate 
        void Proc8(); // PublishCRL

        [PreserveSig] // Opnum 9
        int GetCRL(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            out CERTTRANSBLOB pctbCRL);

        [PreserveSig] // Opnum 10
        int RevokeCertificate(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszSerialNumber,
            uint Reason,
            ulong FileTime);

        void Proc11(); // EnumViewColumn
        void Proc12(); // GetViewDefaultColumnSet
        void Proc13(); // EnumAttributesOrExtensions
        void Proc14(); // OpenView 
        void Proc15(); // EnumView
        void Proc16(); // CloseView
        void Proc17(); // ServerControl

        [PreserveSig] // Opnum 18
        int Ping(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority);

        [PreserveSig] // Opnum 19
        int GetServerState(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            out uint pdwState);

        void Proc20(); // BackupPrepare
        void Proc21(); // BackupEnd
        void Proc22(); // BackupGetAttachmentInformation
        void Proc23(); // BackupGetBackupLogs
        void Proc24(); // BackupOpenFile
        void Proc25(); // BackupReadFile
        void Proc26(); // BackupCloseFile
        void Proc27(); // BackupTruncateLogs
        void Proc28(); // ImportCertificate
        void Proc29(); // BackupGetDynamicFiles
        void Proc30(); // RestoreGetDatabaseLocations

        // ICertAdminD2 (opnum 31 - 48) : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/5980fbc9-5001-42bc-ad09-8759d20ce054
        void Proc31(); // PublishCRLs

        [PreserveSig] // Opnum 32
        int GetCAProperty(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            int PropId,
            int PropIndex,
            int PropType,
            out CERTTRANSBLOB pctbPropertyValue);

        [PreserveSig] // Opnum 33
        int SetCAProperty(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            int PropId,
            int PropIndex,
            int PropType,
            CERTTRANSBLOB pctbPropertyValue);

        [PreserveSig] // Opnum 34
        int GetCAPropertyInfo(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            out int pcProperty,
            out CERTTRANSBLOB pctbPropInfo);

        void Proc35(); // EnumViewColumnTable

        [PreserveSig] // Opnum 36
        int GetCASecurity(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            out CERTTRANSBLOB pctbSD);

        [PreserveSig] // Opnum 37
        int SetCASecurity(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            CERTTRANSBLOB pctbSD);

        [PreserveSig] // Opnum 38
        int Ping2(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority);

        [PreserveSig] // Opnum 39
        int GetArchivedKey(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            uint dwRequestId,
            out CERTTRANSBLOB pctbArchivedKey);

        void Proc40(); // GetAuditFilter
        void Proc41(); // SetAuditFilter

        [PreserveSig] // Opnum 42
        int GetOfficerRights(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            [MarshalAs(UnmanagedType.Bool)] out bool pfEnabled,
            out CERTTRANSBLOB pctbSD);

        [PreserveSig] // Opnum 43
        int SetOfficerRights(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            int fEnable,
            CERTTRANSBLOB pctbSD);

        [PreserveSig] // Opnum 44
        int GetConfigEntry(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszNodePath,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszEntry,
            out object pVariant);

        [PreserveSig] // Opnum 45
        int SetConfigEntry(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszNodePath,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszEntry,
            object pVariant);

        void Proc46(); // ImportKey

        [PreserveSig]
        int GetMyRoles(
            [MarshalAs(UnmanagedType.LPWStr)] string pwszAuthority, 
            out int pdwRoles);

        void Proc48(); // DeleteRow
    }

    internal class CertAdmin
    {
        // d99e6e73-fc88-11d0-b498-00a0c90312f3 - CertSrv Admin (found with OleView .NET)
        private static readonly string CLSID_ICertAdminD = "d99e6e73-fc88-11d0-b498-00a0c90312f3";

        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/1c001aea-dd2c-4845-adf2-9becec00e4c3
        // IID_ICertAdminD = "d99e6e71-fc88-11d0-b498-00a0c90312f3";
        // IID_ICertAdminD2 = "7fe0d935-dda6-443f-85d0-1cfb58fe41dd";

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtQuerySystemTime(out ulong SystemTime);

        private static bool PerformCertAdminAction(string server, string func_name, Func<ICertAdminD2, int> fn)
        {
            var cert_admin = DistributedComUtil.CreateRemoteInstance<ICertAdminD2>(CLSID_ICertAdminD, typeof(ICertAdminD2).GUID, server);

            if (cert_admin == null)
            {
                Console.WriteLine("[X] Could not obtain ICertAdminD2 interface");
                return false;
            }

            var hr = fn(cert_admin);

            if (hr < 0)
            {
                Console.WriteLine($"[X] ICertAdminD2->{func_name} returned hr = {hr:x}");
                return false;
            }

            return true;
        }

        public static bool SetExtension(string server, string authority, uint request_id, string extension_oid, bool critical, byte[] bytes)
        {
            GCHandle gch = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            uint dwType = 0x00000003; // Binary data
            uint dwFlags = critical ? 1u : 0;

            try
            {
                CERTTRANSBLOB temp = new CERTTRANSBLOB()
                {
                    cb = bytes.Length,
                    pb = gch.AddrOfPinnedObject()
                };

                return PerformCertAdminAction(server, "SetExtension", c => c.SetExtension(authority, request_id, extension_oid, dwType, dwFlags, temp));
            }
            finally
            {
                if (gch != null)
                    gch.Free();
            }
        }

        public static bool SetAttribute(string server, string authority, uint request_id, string attributes)
        {
            return PerformCertAdminAction(server, "SetAttributes", c => c.SetAttributes(authority, request_id, attributes));
        }

        public static bool IssueRequest(string server, string authority, uint request_id)
        {
            uint disposition = 0;

            if (!PerformCertAdminAction(server, "ResubmitRequest", c => c.ResubmitRequest(authority, request_id, out disposition)))
                return false;

            switch (disposition)
            {
                case 0x80094004: // CERTSRV_E_PROPERTY_EMPTY
                    // If the request is not found, the CA MUST place 0x80094004 in the pdwDisposition parameter and return successfully.
                    Console.WriteLine($"[X] The certificate request with ID = '{request_id}' does not exist.");
                    return false;

                case 0x80094003: // CERTSRV_E_BAD_REQUESTSTATUS
                    // If the value of the Request_Disposition column in the identified row is not "request pending" or "request denied", the CA MUST place 0x80094003 in the pdwDisposition parameter and return successfully.
                    // If the value of the Request_Disposition column in the identified row is "request denied" and the invoker of the method is not the CA administrator, the CA MUST place 0x80094003 in the pdwDisposition parameter and return successfully.
                    Console.WriteLine($"[X] The certificate request with ID = '{request_id}' is not pending or the request has been denied and you are not a CA administrator.");
                    return false;

                case 0: // CR_DISP_INCOMPLETE
                    Console.WriteLine($"[X] The certificate request with ID = '{request_id}' was incomplete.");
                    return false;

                case 1: // CR_DISP_ERROR
                    Console.WriteLine($"[X] The certificate request with ID = '{request_id}' has failed.");
                    return false;

                case 2: // CR_DISP_DENIED
                    Console.WriteLine($"[X] The certificate request with ID = '{request_id}' was denied.");
                    return false;

                case 3: // CR_DISP_ISSUED
                    Console.WriteLine($"[+] The certificate request with ID = '{request_id}' was issued.");
                    return true;

                case 5: // CR_DISP_UNDER_SUBMISSION
                    Console.WriteLine($"[*] The certificate request with ID = '{request_id}' is pending.");
                    return true;

                default:
                    Console.WriteLine($"[X] The certificate request with ID = '{request_id}' failed with error = '{disposition:x}'.");
                    return false;
            }
        }

        public static bool DenyRequest(string server, string authority, uint request_id)
        {
            return PerformCertAdminAction(server, "DenyRequest", c => c.DenyRequest(authority, request_id));
        }

        public static bool RevokeCertificate(string server, string authority, string serial)
        {
            if (NtQuerySystemTime(out ulong filetime) < 0)
                return false;

            return PerformCertAdminAction(server, "RevokeCertificate", c => c.RevokeCertificate(authority, serial, 0 /* CRL_REASON_UNSPECIFIED */, filetime));
        }

        public static bool GetCaType(string server, string authority, out int? ca_type)
        {
            var CR_PROP_CATYPE = 0x0000000A;
            var PROPTYPE_LONG = 0x00000001;

            var temp = new CERTTRANSBLOB();
            ca_type = null;

            if (!PerformCertAdminAction(server, "GetCAProperty", c => c.GetCAProperty(authority, CR_PROP_CATYPE, 0, PROPTYPE_LONG, out temp)))
                return false;

            var ca_info = Marshal.PtrToStructure<CAINFO>(temp.pb);
            ca_type = ca_info.CAType;
            return true;
        }

        public static bool GetTemplates(string server, string authority, out string templates)
        {
            var CR_PROP_TEMPLATES = 0x0000001D;
            var PROPTYPE_STRING = 0x00000004;

            var temp = new CERTTRANSBLOB();
            templates = string.Empty;

            if (!PerformCertAdminAction(server, "GetCAProperty", c => c.GetCAProperty(authority, CR_PROP_TEMPLATES, 0, PROPTYPE_STRING, out temp)))
                return false;

            templates = Marshal.PtrToStringUni(temp.pb, temp.cb / 2);
            return true;
        }

        public static bool SetTemplates(string server, string authority, string templates)
        {
            var CR_PROP_TEMPLATES = 0x0000001D;
            var PROPTYPE_STRING = 0x00000004;

            var bytes = Encoding.Unicode.GetBytes(templates + char.MinValue);
            GCHandle gch = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            try
            {
                CERTTRANSBLOB temp = new CERTTRANSBLOB()
                {
                    cb = bytes.Length,
                    pb = gch.AddrOfPinnedObject()
                };

                return PerformCertAdminAction(server, "SetCAProperty", c => c.SetCAProperty(authority, CR_PROP_TEMPLATES, 0, PROPTYPE_STRING, temp));
            }
            finally
            {
                if (gch != null)
                    gch.Free();
            }
        }

        public static bool GetCASecurity(string server, string authority, out ActiveDirectorySecurity security_descriptor)
        {
            CERTTRANSBLOB temp = new CERTTRANSBLOB();
            security_descriptor = new ActiveDirectorySecurity();

            if (!PerformCertAdminAction(server, "GetCASecurity", c => c.GetCASecurity(authority, out temp)))
                return false;

            var bytes = new byte[temp.cb];
            Marshal.Copy(temp.pb, bytes, 0, temp.cb);

            security_descriptor.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.All);
            return true;
        }

        public static bool SetCASecurity(string server, string authority, ActiveDirectorySecurity security_descriptor)
        {
            var bytes = security_descriptor.GetSecurityDescriptorBinaryForm();

            if (bytes == null)
                return false;

            GCHandle gch = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            try
            {
                CERTTRANSBLOB temp = new CERTTRANSBLOB()
                {
                    cb = bytes.Length,
                    pb = gch.AddrOfPinnedObject()
                };

                return PerformCertAdminAction(server, "SetCASecurity", c => c.SetCASecurity(authority, temp));
            }
            finally
            {
                if (gch != null)
                    gch.Free();
            }
        }

        public static bool GetArchivedKey(string server, string authority, uint request_id, out byte[] encrypted_pkcs7)
        {
            CERTTRANSBLOB temp = new CERTTRANSBLOB();
            encrypted_pkcs7 = null;

            if (!PerformCertAdminAction(server, "GetArchivedKey", c => c.GetArchivedKey(authority, request_id, out temp)))
                return false;

            encrypted_pkcs7 = new byte[temp.cb];
            Marshal.Copy(temp.pb, encrypted_pkcs7, 0, temp.cb);
            return true;
        }

        public static bool GetOfficerRights(string server, string authority, out bool enabled, out ActiveDirectorySecurity security_descriptor)
        {
            enabled = false;
            security_descriptor = new ActiveDirectorySecurity();
  
            var temp1 = false;
            var temp2 = new CERTTRANSBLOB();

            if (!PerformCertAdminAction(server, "GetOfficerRights", c => c.GetOfficerRights(authority, out temp1, out temp2)) || !temp1)
                return false;

            var bytes = new byte[temp2.cb];
            Marshal.Copy(temp2.pb, bytes, 0, temp2.cb);

            enabled = temp1;
            security_descriptor.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.All);
            return true;
        }

        public static bool SetOfficerRights(string server, string authority, bool enabled, bool ea_or_officer, ActiveDirectorySecurity security_descriptor)
        {
            var bytes = security_descriptor.GetSecurityDescriptorBinaryForm();

            if (bytes == null)
                return false;

            GCHandle gch = GCHandle.Alloc(bytes, GCHandleType.Pinned);

            try
            {
                // F - fRightsEnable: If bits 0 through 15 are 0, then disable access rights (officer or enrollment agent) and ignore the value of pctbSD.
                // R - RightsType: If bits 16 through 31 are 0, then the security descriptor in the pctbSD parameter is for officer rights.
                //                 If bits 16 through 31 are nonzero, the security descriptor in the pctbSD is for the enrollment agents.
                int enable = (Convert.ToInt32(ea_or_officer) << 16) | Convert.ToInt32(enabled);

                CERTTRANSBLOB temp = new CERTTRANSBLOB()
                {
                    cb = bytes.Length,
                    pb = gch.AddrOfPinnedObject()
                };

                return PerformCertAdminAction(server, "SetOfficerRights", c => c.SetOfficerRights(authority, enable, temp));
            }
            finally
            {
                if (gch != null)
                    gch.Free();
            }
        }

        public static bool GetConfigEntry<T>(string server, string authority, string node_path, string entry, out T variant)
        {
            variant = default;

            object temp = null;

            if (!PerformCertAdminAction(server, "GetConfigEntry", c => c.GetConfigEntry(authority, node_path ?? string.Empty, entry ?? string.Empty, out temp)))
                return false;

            variant = (T)temp;
            return true;
        }

        public static bool SetConfigEntry<T>(string server, string authority, string node_path, string entry, T variant)
        {
            return PerformCertAdminAction(server, "SetConfigEntry", c => c.SetConfigEntry(authority, node_path ?? string.Empty, entry ?? string.Empty, variant));
        }

        public static bool GetMyRoles(string server, string authority, out CertificationAuthorityRights result)
        {
            int temp = 0;

            try
            {
                return PerformCertAdminAction(server, "GetMyRoles", c => c.GetMyRoles(authority, out temp));
            }
            finally
            {
                result = (CertificationAuthorityRights)temp;
            }
        }
    }
}

#endif