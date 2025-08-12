using System;
using System.Runtime.InteropServices;

#if !DISARMED

namespace Certify.Lib
{
    internal class DistributedComUtil
    {
        [Flags]
        enum CLSCTX : uint
        {
            CLSCTX_REMOTE_SERVER = 0x10,
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct COSERVERINFO
        {
            public uint dwReserved1;
            public string pwszName;
            public IntPtr pAuthInfo;
            public uint dwReserved2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MULTI_QI
        {
            public IntPtr pIID;
            [MarshalAs(UnmanagedType.IUnknown)] public object pItf;
            public int hr;
        }

        [DllImport("ole32.dll")]
        private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);

        [DllImport("ole32.dll")]
        private static extern int CoInitializeSecurity(IntPtr pSecDesc, int cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1, uint dwAuthnLevel, uint dwImpLevel, IntPtr pAuthList, uint dwCapabilities, IntPtr pReserved3);

        [DllImport("ole32.dll")]
        private static extern int CoCreateInstanceEx([In, MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, [MarshalAs(UnmanagedType.IUnknown)] object pUnkOuter, CLSCTX dwClsCtx, ref COSERVERINFO pServerInfo, uint dwCount, [In, Out] MULTI_QI[] pResults);

        public static bool Initialize()
        {
            var hr = CoInitializeEx(IntPtr.Zero, 0 /* COINIT_MULTITHREADED */);

            if ((uint)hr == 0x80010106 /* RPC_E_CHANGED_MODE */)
            {
                Console.WriteLine($"[!] CoInitialize changed thread model. DCOM-related actions may not work as intended.");
            }
            else if (hr < 0)
            {
                Console.WriteLine($"[!] CoInitialize failed with hr = {hr:x}");
            }

            return true;
        }

        public static bool InitializeSecurity()
        {
            // Initialize the DCOM security values (RPC_C_IMP_LEVEL_IMPERSONATE is important)
            uint auth_level = 6; // RPC_C_AUTHN_LEVEL_PKT_PRIVACY
            uint imps_level = 3; // RPC_C_IMP_LEVEL_IMPERSONATE

            var hr = CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, auth_level, imps_level, IntPtr.Zero, 0 /* EOAC_NONE */, IntPtr.Zero);

            if ((uint)hr == 0x80010119 /* RPC_E_TOO_LATE */)
            {
                Console.WriteLine("[!] CoInitializeSecurity has already been called. DCOM-related actions may not work as intended.");
                return false;
            }
            else if (hr < 0)
            {
                Console.WriteLine($"[!] CoInitializeSecurity failed with hr = {hr:x}");
                return false;
            }

            return true;
        }

        public static T CreateRemoteInstance<T>(string clsid, Guid iid, string server) where T : class
        {
            var server_info = new COSERVERINFO()
            {
                pwszName = server,
            };

            IntPtr pIID = IntPtr.Zero;

            try
            {
                pIID = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(Guid)));
                Marshal.StructureToPtr(iid, pIID, false);

                var mqi = new MULTI_QI[1];
                mqi[0].pIID = pIID;
                mqi[0].pItf = null;
                mqi[0].hr = 0;

                var hr = CoCreateInstanceEx(Guid.Parse(clsid), null, CLSCTX.CLSCTX_REMOTE_SERVER, ref server_info, 1, mqi);

                if (hr != 0)
                {
                    Console.WriteLine($"CoCreateInstanceEx failed with hr = {hr:x}");
                    return null;
                }

                return (T)mqi[0].pItf;
            }
            finally
            {
                Marshal.FreeCoTaskMem(pIID);
            }
        }
    }
}

#endif