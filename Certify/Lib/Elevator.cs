using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Certify.Lib
{
    internal class Elevator
    {
        // returns true if the current process is running with adminstrative privs in a high integrity context
        private static bool IsHighIntegrity()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        // helper to elevate to SYSTEM via token impersonation
        private static void ImpersonateWinlogon()
        {
            var processes = Process.GetProcessesByName("winlogon");
            var handle = processes[0].Handle;

            // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
            // TOKEN_DUPLICATE = 0x0002
            var success = Interop.OpenProcessToken(handle, 0x0002, out var hProcToken);
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                throw new Exception($"OpenProcessToken failed with the following error: {errorCode}");
            }

            // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
            // 2 == SecurityImpersonation
            var hDupToken = IntPtr.Zero;
            success = Interop.DuplicateToken(hProcToken, 2, ref hDupToken);
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                Interop.CloseHandle(hProcToken);
                throw new Exception($"DuplicateToken failed with the following error: {errorCode}");
            }

            success = Interop.ImpersonateLoggedOnUser(hDupToken);
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                Interop.CloseHandle(hProcToken);
                Interop.CloseHandle(hDupToken);
                throw new Exception($"ImpersonateLoggedOnUser failed with the following error: {errorCode}");
            }

            // clean up the handles we created
            Interop.CloseHandle(hProcToken);
            Interop.CloseHandle(hDupToken);

            var name = WindowsIdentity.GetCurrent().Name;

            if (name != "NT AUTHORITY\\SYSTEM")
                throw new Exception($"ImpersonateLoggedOnUser worked, but thread is not running as SYSTEM");
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
                Interop.RevertToSelf();
            }
        }
    }
}
