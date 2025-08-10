using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace Certify.Domain
{
    class EnrollmentAgentRestriction
    {
        public string Agent { get; }
        public string Template { get; }
        public List<string> Targets { get; } = new List<string>();

        public EnrollmentAgentRestriction(CommonAce ace)
        {
            Agent = ace.SecurityIdentifier.ToString();

            var bytes = ace.GetOpaque();

            var index = 0;
            var sid_count = BitConverter.ToUInt32(bytes, index);
            index += 4;

            for (var i = 0; i < sid_count; ++i)
            {
                var sid = new SecurityIdentifier(bytes, index);
                Targets.Add(sid.ToString());
                index += sid.BinaryLength;
            }

            if (index < bytes.Length)
                Template = Encoding.Unicode.GetString(bytes, index, (bytes.Length - index - 2)).Replace("\u0000", string.Empty);
            else
                Template = "<All>";
        }
    }
}
