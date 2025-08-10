using System.Text.RegularExpressions;

namespace Certify.Lib
{
    internal class SidUtil
    {
        public static bool IsAdminSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$")
                   || sid == "S-1-5-9"
                   || sid == "S-1-5-32-544";
        }

        public static bool IsLowPrivSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(513|515|545)$") // Domain Users, Domain Computers, Users
                || sid == "S-1-1-0"   // Everyone
                || sid == "S-1-5-11"; // Authenticated Users
        }

        public static bool IsValidSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-\d+(-\d+){1,15}$", RegexOptions.IgnoreCase);
        }
    }
}
