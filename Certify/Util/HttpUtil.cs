using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;

namespace Certify.Lib
{
    internal class HttpUtil
    {
        struct SECURITY_INTEGER
        {
            public uint LowPart;
            public uint HighPart;
        };

        struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        };

        struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;

            public SecBuffer(int size)
                : this(new byte[size])
            {

            }

            public SecBuffer(byte[] bytes) 
                : this(bytes, 2)
            {
              
            }

            public SecBuffer(byte[] bytes, int type)
            {
                cbBuffer = bytes.Length;
                BufferType = type;

                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(bytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        struct SecBufferDesc : IDisposable
        {
            public uint ulVersion;
            public uint cBuffers;
            public IntPtr pBuffers;

            public SecBufferDesc(int size)
            {
                ulVersion = 0;
                cBuffers = 1;

                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
                Marshal.StructureToPtr(new SecBuffer(size), pBuffers, false);
            }

            public SecBufferDesc(byte[] bytes)
            {
                ulVersion = 0;
                cBuffers = 1;

                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
                Marshal.StructureToPtr(new SecBuffer(bytes), pBuffers, false);
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    if (cBuffers == 1)
                        Marshal.PtrToStructure<SecBuffer>(pBuffers).Dispose();
                    else
                    {
                        for (int i = 0; i < cBuffers; i++)
                            Marshal.FreeHGlobal(Marshal.ReadIntPtr(pBuffers, (Marshal.SizeOf<SecBuffer>() * i) + (Marshal.SizeOf<uint>() * 2)));
                    }

                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public byte[] GetSecBufferByteArray()
            {
                byte[] result = null;

                if (pBuffers == IntPtr.Zero)
                    throw new InvalidOperationException("Object has already been disposed!!!");

                if (cBuffers == 1)
                {
                    var buffer = Marshal.PtrToStructure<SecBuffer>(pBuffers);

                    if (buffer.cbBuffer > 0)
                    {
                        result = new byte[buffer.cbBuffer];
                        Marshal.Copy(buffer.pvBuffer, result, 0, buffer.cbBuffer);
                    }
                }
                else
                {
                    int total_size = 0;

                    for (int i = 0; i < cBuffers; i++)
                        total_size += Marshal.ReadInt32(pBuffers, Marshal.SizeOf<SecBuffer>() * i);

                    result = new byte[total_size];

                    for (int i = 0, offset = 0; i < cBuffers; i++)
                    {
                        int size = Marshal.ReadInt32(pBuffers, Marshal.SizeOf<SecBuffer>() * i);
                        var buffer = Marshal.ReadIntPtr(pBuffers, (Marshal.SizeOf<SecBuffer>() * i) + (Marshal.SizeOf<uint>() * 2));

                        Marshal.Copy(buffer, result, offset, size);
                        offset += size;
                    }
                }

                return result;
            }
        }

        [DllImport("secur32.dll")]
        static extern int AcquireCredentialsHandle(string pszPrincipal, string pszPackage, uint fCredentialUse, IntPtr pvLogonID, IntPtr pAuthData, 
            IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, out SECURITY_HANDLE phCredential, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(SECURITY_HANDLE phCredential, IntPtr phContext, string pszTargetName, uint fContextReq, uint Reserved1,
            uint TargetDataRep, IntPtr pInput, uint Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out uint pfContextAttr, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(SECURITY_HANDLE phCredential, SECURITY_HANDLE phContext, string pszTargetName, uint fContextReq, uint Reserved1,
            uint TargetDataRep, SecBufferDesc pInput, uint Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out uint pfContextAttr, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll")]
        static extern int DeleteSecurityContext(SECURITY_HANDLE phContext);

        [DllImport("secur32.dll")]
        static extern int FreeCredentialsHandle(SECURITY_HANDLE phCredential);

        const int MAX_TOKEN_SIZE = 12288;

        public static bool AuthWithChannelBinding(string url)
        {
            var handler = new HttpClientHandler
            {
                Credentials = new CredentialCache() { { new Uri(url), "NTLM", CredentialCache.DefaultNetworkCredentials } },
                PreAuthenticate = true,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            using (var client = new HttpClient(handler))
            {
                try
                {
                    var response = SynchronizeHttpTask(() => client.GetAsync(url));
                    return response.StatusCode == HttpStatusCode.OK;
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[X] AuthWithChannelBinding HTTP request for URL '{url}' failed with error: {e.Message}");
                    return false;
                }
            }
        }

        public static bool AuthWithoutChannelBinding(string url)
        {
            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = false,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            using (var client = new HttpClient(handler))
            {
                if (AcquireCredentialsHandle(WindowsIdentity.GetCurrent().Name, "NTLM", 2 /* SECPKG_CRED_OUTBOUND */, IntPtr.Zero,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out SECURITY_HANDLE CredHandle, out SECURITY_INTEGER ClientLifeTime) != 0)
                {
                    Console.WriteLine("[X] AuthWithoutChannelBinding: failed to acquire credentials handle.");
                    return false;
                }

                var ClientContext = new SECURITY_HANDLE()
                {
                    LowPart = IntPtr.Zero,
                    HighPart = IntPtr.Zero
                };

                try
                {
                    string ntlm_message = HttpInitializeSecurityContext(CredHandle, ref ClientContext, out uint ContextAttributes, out SECURITY_INTEGER ClientLifetime, null);
                    
                    if (string.IsNullOrEmpty(ntlm_message))
                        return false;

                    var request_message = new HttpRequestMessage(HttpMethod.Get, url);
                    request_message.Headers.Add("Authorization", ntlm_message);

                    try
                    {
                        var response = SynchronizeHttpTask(() => client.SendAsync(request_message));

                        if (!response.Headers.Contains("WWW-Authenticate"))
                        {
                            Console.WriteLine("[X] AuthWithoutChannelBinding: did not receive an NTLM message in HTTP response.");
                            return false;
                        }

                        ntlm_message = response.Headers.GetValues("WWW-Authenticate").First();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[X] AuthWithoutChannelBinding HTTP request for URL '{url}' failed with error: {e.Message}");
                        return false;
                    }

                    ntlm_message = HttpInitializeSecurityContext(CredHandle, ref ClientContext, out ContextAttributes, out ClientLifetime, ntlm_message);

                    if (string.IsNullOrEmpty(ntlm_message))
                        return false;
                    
                    request_message = new HttpRequestMessage(HttpMethod.Get, url);
                    request_message.Headers.Add("Authorization", ntlm_message);

                    try
                    {
                        var response = SynchronizeHttpTask(() => client.SendAsync(request_message));
                        return response.StatusCode == HttpStatusCode.OK;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[X] AuthWithoutChannelBinding HTTP request for URL '{url}' failed with error: {e.Message}");
                        return false;
                    }
                }
                finally
                {
                    if (ClientContext.LowPart != IntPtr.Zero || ClientContext.HighPart != IntPtr.Zero)
                        DeleteSecurityContext(ClientContext);

                    if (CredHandle.LowPart != IntPtr.Zero || CredHandle.HighPart != IntPtr.Zero)
                        FreeCredentialsHandle(CredHandle);
                }
            }
        }

        private static string HttpInitializeSecurityContext(SECURITY_HANDLE CredHandle, ref SECURITY_HANDLE ClientContext, out uint ContextAttributes, out SECURITY_INTEGER ClientLifeTime, string message)
        {
            SecBufferDesc ClientToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            if (message == null)
            {
                int res = InitializeSecurityContext(CredHandle, IntPtr.Zero, WindowsIdentity.GetCurrent().Name, 0x00000800 /* ISC_REQ_CONNECTION */, 0, 
                    0x10 /* SECURITY_NATIVE_DREP */, IntPtr.Zero, 0, out ClientContext, out ClientToken, out ContextAttributes, out ClientLifeTime);

                if (res != 0x00090312) // SEC_I_CONTINUE_NEEDED 
                {
                    Console.WriteLine($"[X] HttpInitializeSecurityContext: failed with result = 0x{res:x}.");
                    return null;
                }
            }
            else
            {
                var ServerToken = new SecBufferDesc(Convert.FromBase64String(message.Replace("NTLM ", "")));

                int res = InitializeSecurityContext(CredHandle, ClientContext, WindowsIdentity.GetCurrent().Name, 0x00000800 /* ISC_REQ_CONNECTION */, 0, 
                    0x10 /* SECURITY_NATIVE_DREP */, ServerToken, 0, out ClientContext, out ClientToken, out ContextAttributes, out ClientLifeTime);
                
                if (res != 0x00000000) // SEC_E_OK  
                {
                    Console.WriteLine($"[X] HttpInitializeSecurityContext: failed with result = 0x{res:x}.");
                    return null;
                }
            }

            byte[] ntlm_message = ClientToken.GetSecBufferByteArray();
            return $"NTLM {Convert.ToBase64String(ntlm_message)}";
        }

        private static HttpResponseMessage SynchronizeHttpTask(Func<Task<HttpResponseMessage>> fn)
        {
            var task = Task.Run(() => fn());

            try
            {
                task.Wait();
                return task.Result;
            }
            catch (AggregateException e)
            {
                throw e.InnerException ?? e;
            }
        }
    }
}