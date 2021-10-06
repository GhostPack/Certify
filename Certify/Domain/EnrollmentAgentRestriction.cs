using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Certify.Lib;
using Microsoft.Win32;
using System.Text;

namespace Certify.Domain
{
    class EnrollmentAgentRestriction
    {
        public string Agent { get; }

        public string Template { get; }

        public List<string> Targets { get; }

        public EnrollmentAgentRestriction(CommonAce ace)
        {
            Targets = new List<string>();
            var index = 0;

            Agent = ace.SecurityIdentifier.ToString();
            var bytes = ace.GetOpaque();

            var sidCount = BitConverter.ToUInt32(bytes, index);
            index += 4;

            for (var i = 0; i < sidCount; ++i)
            {
                var sid = new SecurityIdentifier(bytes, index);
                Targets.Add(sid.ToString());
                index += sid.BinaryLength;
            }

            if (index < bytes.Length)
            {
                Template = Encoding.Unicode.GetString(bytes, index, (bytes.Length - index - 2)).Replace("\u0000", string.Empty);
            }
            else
            {
                Template = "<All>";
            }
        }
    }
}
