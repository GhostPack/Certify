using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

#if !DISARMED

namespace Certify.Lib
{
    // Allows running a block of code impersonated as a different Windows user.
    // Usage:
    //   using (ImpersonationHelper.Impersonate(username, domain, password))
    //   {
    //       // code runs as the supplied user
    //   }
    //   // back to original identity here
    internal class ImpersonationHelper : IDisposable
    {
        private readonly WindowsImpersonationContext _context;
        private readonly SafeTokenHandle _token;

        private const int LOGON32_LOGON_NEW_CREDENTIALS = 9; // best for network access to remote resources
        private const int LOGON32_PROVIDER_WINNT50 = 3;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out SafeTokenHandle phToken);

        private ImpersonationHelper(WindowsImpersonationContext context, SafeTokenHandle token)
        {
            _context = context;
            _token = token;
        }

        // Returns null if username is empty — callers can use it in a null-safe using block
        public static ImpersonationHelper Impersonate(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
                return null;

            // Split domain\user or user@domain into parts LogonUser expects
            string domain = ".";
            string user = username;

            if (username.Contains("\\"))
            {
                var parts = username.Split(new[] { '\\' }, 2);
                domain = parts[0];
                user = parts[1];
            }
            else if (username.Contains("@"))
            {
                // UPN format — pass as-is with empty domain
                domain = string.Empty;
                user = username;
            }

            if (!LogonUser(user, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, out var token))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                    $"LogonUser failed for '{username}'. Check credentials.");

            var identity = new WindowsIdentity(token.DangerousGetHandle());
            var context = identity.Impersonate();

            return new ImpersonationHelper(context, token);
        }

        public void Dispose()
        {
            _context?.Undo();
            _context?.Dispose();
            _token?.Dispose();
        }
    }

    // Safe wrapper around a Win32 token handle
    internal class SafeTokenHandle : SafeHandle
    {
        private SafeTokenHandle() : base(IntPtr.Zero, true) { }

        public override bool IsInvalid => handle == IntPtr.Zero;

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }
}

#endif