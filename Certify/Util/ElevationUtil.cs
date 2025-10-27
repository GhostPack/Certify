using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Certify.Lib
{
    internal class ElevationUtil
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool RevertToSelf();

        // returns true if the current process is running with adminstrative privs in a high integrity context
        private static bool IsHighIntegrity()
        {
            var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        // helper to elevate to SYSTEM via token impersonation
        private static void ImpersonateWinlogon()
        {
            var name = string.Empty;
            var processes = Process.GetProcessesByName("winlogon");

            foreach (var process in processes)
            {
                IntPtr hProcToken = IntPtr.Zero;

                try
                {
                    // Open winlogon's token with TOKEN_DUPLICATE accesss so we can make a copy of the token with DuplicateToken
                    if (!OpenProcessToken(process.Handle, 0x0002 /* TOKEN_DUPLICATE */, out hProcToken))
                    {
                        Console.WriteLine($"[!] OpenProcessToken failed with the following error: {Marshal.GetLastWin32Error()}");
                        continue;
                    }

                    // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                    var hDupToken = IntPtr.Zero;

                    try
                    {
                        if (!DuplicateToken(hProcToken, 2 /* SecurityImpersonation */, ref hDupToken))
                        {
                            Console.WriteLine($"[!] DuplicateToken failed with the following error: {Marshal.GetLastWin32Error()}");
                            continue;
                        }

                        if (!ImpersonateLoggedOnUser(hDupToken))
                        {
                            Console.WriteLine($"[!] ImpersonateLoggedOnUser failed with the following error: {Marshal.GetLastWin32Error()}");
                            continue;
                        }

                        if (WindowsIdentity.GetCurrent().Name != "NT AUTHORITY\\SYSTEM")
                            throw new Exception($"ImpersonateLoggedOnUser worked, but thread is not running as SYSTEM");
                    }
                    finally
                    {
                        if (hDupToken != IntPtr.Zero)
                            CloseHandle(hDupToken);
                    }
                }
                finally
                {
                    if (hProcToken != IntPtr.Zero)
                        CloseHandle(hProcToken);
                }
            }
        }

        public static void GetSystem(Action action)
        {
            if (!IsHighIntegrity())
                throw new AccessViolationException("Need to be in an elevated context");

            ImpersonateWinlogon();

            try
            {
                action();
            }
            finally
            {
                RevertToSelf();
            }
        }
    }
}
