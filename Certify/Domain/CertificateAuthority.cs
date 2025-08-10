using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Cryptography.X509Certificates;

namespace Certify.Domain
{
    // From https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/509360cf-9797-491e-9dd1-795f63cb1538
    [Flags]
    public enum CertificationAuthorityRights : uint
    {
        ManageCA = 1,               // Administrator
        ManageCertificates = 2,     // Officer
        Auditor = 4,
        Operator = 8,
        Read = 256,
        Enroll = 512,
    }

    // From certca.h in the Windows SDK
    [Flags]
    public enum PkiCertificateAuthorityFlags : uint
    {
        NO_TEMPLATE_SUPPORT = 0x00000001,
        SUPPORTS_NT_AUTHENTICATION = 0x00000002,
        CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004,
        CA_SERVERTYPE_ADVANCED = 0x00000008,
    }

    public class CertificateAuthority : ADObject, IDisposable
    {
        public string Name { get; }
        public string DomainName { get; }

        public Guid Guid { get; }
        public PkiCertificateAuthorityFlags Flags { get; }
        public List<X509Certificate2> Certificates { get; }

        public CertificateAuthority(string dn, string name, string domain, Guid guid, PkiCertificateAuthorityFlags flags, 
            List<X509Certificate2> certificates, ActiveDirectorySecurity security_descriptor) 
            : base(dn, security_descriptor)
        {
            Name = name;
            DomainName = domain;

            Guid = guid;
            Flags = flags;
            Certificates = certificates;
        }

        public void Dispose()
        {
            if (Certificates != null)
            {
                foreach (var cert in Certificates)
                    cert.Dispose();

                Certificates.Clear();
            }

            GC.SuppressFinalize(this);
        }
    }
}
