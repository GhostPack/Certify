using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.RegularExpressions;
using Certify.Domain;

namespace Certify.Lib
{
    class DisplayUtil
    {
        public static void PrintEnterpriseCaInfo(EnterpriseCertificateAuthority ca, bool hideAdmins, bool showAllPermissions, List<string>? currentUserSids = null)
        {
            Console.WriteLine($"    Enterprise CA Name            : {ca?.Name}");
            Console.WriteLine($"    DNS Hostname                  : {ca?.DnsHostname}");
            Console.WriteLine($"    FullName                      : {ca?.FullName}");
            Console.WriteLine($"    Flags                         : {ca?.Flags}");

            if (ca == null) throw new NullReferenceException("CA is null");
            ca.Certificates?.ForEach(PrintCertificateInfo);

            var userSpecifiesSanEnabled = false;
            string? errorMessage = null;
            try
            {
                userSpecifiesSanEnabled = ca.IsUserSpecifiesSanEnabled();
            }
            catch (Exception e)
            {
                errorMessage = e.Message;
            }

            Console.WriteLine($"    {GetSanString(userSpecifiesSanEnabled, errorMessage)}");

            Console.WriteLine("    CA Permissions                :");
            var securityDescriptor = ca.GetServerSecurityFromRegistry();

            if (securityDescriptor == null) return;

            var rules = securityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var ownerSid = securityDescriptor.GetOwner(typeof(SecurityIdentifier));
            var ownerName = $"{GetUserSidString(ownerSid.ToString())}";


            Console.WriteLine($"      Owner: {ownerName}");
            if (currentUserSids == null)
            {
                if (IsLowPrivSid(ownerSid.ToString()))
                {
                    Console.WriteLine($"        [!] Owner is a low-privilged principal!");
                }
            }
            else
            {
                if (currentUserSids.Contains(ownerSid.ToString()))
                {
                    Console.WriteLine($"        [!] Owner is current user or a group they are a member of!");
                }
            }

            Console.WriteLine();

            if (!showAllPermissions) Console.WriteLine($"      {"Access",-6} {"Rights",-42} Principal\n");

            foreach (ActiveDirectoryAccessRule rule in rules)
            {
                var sid = rule.IdentityReference.ToString();
                var rights = (CertificationAuthorityRights)rule.ActiveDirectoryRights;

                if (hideAdmins && IsAdminSid(sid)) continue;

                if (showAllPermissions)
                {
                    Console.WriteLine($"      Identity                    : {GetUserSidString(sid)}");
                    Console.WriteLine($"        AccessControlType         : {rule.AccessControlType}");
                    Console.WriteLine($"        Rights                    : {rights}");
                    Console.WriteLine($"        ObjectType                : {rule.ObjectType}");
                    Console.WriteLine($"        IsInherited               : {rule.IsInherited}");
                    Console.WriteLine($"        InheritedObjectType       : {rule.InheritedObjectType}");
                    Console.WriteLine($"        InheritanceFlags          : {rule.InheritanceFlags}");
                    Console.WriteLine($"        PropagationFlags          : {rule.PropagationFlags}");
                }
                else
                {
                    Console.WriteLine($"      {rule.AccessControlType,-6} {rights,-42} {GetUserSidString(sid)}");
                }

                if (currentUserSids == null)
                {
                    if (IsLowPrivSid(sid))
                    {
                        if (((rights & CertificationAuthorityRights.ManageCA) == CertificationAuthorityRights.ManageCA))
                        {
                            Console.WriteLine($"        [!] Low-privileged principal has ManageCA rights!");
                        }
                        else if (((rights & CertificationAuthorityRights.ManageCertificates) == CertificationAuthorityRights.ManageCertificates))
                        {
                            Console.WriteLine($"        [!] Low-privileged principal has ManageCertificates rights!");
                        }
                    }
                }
                else
                {
                    if (currentUserSids.Contains(sid))
                        {
                        if (((rights & CertificationAuthorityRights.ManageCA) == CertificationAuthorityRights.ManageCA))
                        {
                            Console.WriteLine($"        [!] Current user (or a group they are a member of) has ManageCA rights!");
                        }
                        else if (((rights & CertificationAuthorityRights.ManageCertificates) == CertificationAuthorityRights.ManageCertificates))
                        {
                            Console.WriteLine($"        [!] Current user (or a group they are a member of) has ManageCertificates rights!");
                        }
                    }
                }
            }

            // bit more complicated than anticipated, as template names can be emebedded in the DACL
            //   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/b497b1e1-a84c-40c8-9379-524193176fad
            var eaSecurityDescriptor = ca.GetEnrollmentAgentSecurity();

            if (eaSecurityDescriptor == null)
            {
                Console.WriteLine("    Enrollment Agent Restrictions : None");
            }
            else
            {
                Console.WriteLine("    Enrollment Agent Restrictions :");

                foreach (CommonAce ace in eaSecurityDescriptor.DiscretionaryAcl)
                {
                    var entry = new EnrollmentAgentRestriction(ace);
                    Console.WriteLine($"      {GetUserSidString(entry.Agent)}");
                    Console.WriteLine($"        Template : {entry.Template}");
                    Console.WriteLine($"        Targets  :");
                    foreach (var target in entry.Targets)
                    {
                        Console.WriteLine($"          {GetUserSidString(target, 26)}");
                    }
                    Console.WriteLine();
                }
            }
        }

        public static void PrintPKIObjectControllers(IEnumerable<PKIObject> pkiObjects, bool hideAdmins)
        {
            var objectControllers = new SortedDictionary<string, ArrayList>();

            foreach (var pkiObject in pkiObjects)
            {
                if (pkiObject.SecurityDescriptor == null) continue;

                var ownerSid = pkiObject.SecurityDescriptor.GetOwner(typeof(SecurityIdentifier));
                var owner = ownerSid;
                try
                {
                    owner = pkiObject.SecurityDescriptor.GetOwner(typeof(NTAccount));
                }
                catch
                {
                    owner = null;
                }

                var ownerKey = $"{owner}\t{ownerSid}";
                    
                if(!objectControllers.ContainsKey(ownerKey))
                {
                    objectControllers[ownerKey] = new ArrayList();
                }

                objectControllers[ownerKey].Add(new[] { "Owner", pkiObject .DistinguishedName});

                var aces = pkiObject.SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule ace in aces)
                {
                    var principalSid = ace.IdentityReference.ToString();
                    var principalName = GetUserNameFromSid(principalSid);
                    var rights = ace.ActiveDirectoryRights;

                    var principalKey = $"{principalName}\t{principalSid}";

                    if (!objectControllers.ContainsKey(principalKey))
                    {
                        objectControllers[principalKey] = new ArrayList();
                    }

                    if (rights.HasFlag(ActiveDirectoryRights.GenericAll))
                    {
                        objectControllers[principalKey].Add(new[] { "GenericAll", pkiObject.DistinguishedName });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteOwner))
                    {
                        objectControllers[principalKey].Add(new[] { "WriteOwner", pkiObject.DistinguishedName });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteDacl))
                    {
                        objectControllers[principalKey].Add(new[] { "WriteDacl", pkiObject.DistinguishedName });
                    }
                    else if (rights.HasFlag(ActiveDirectoryRights.WriteProperty) && ($"{ace.ObjectType}" == "00000000-0000-0000-0000-000000000000"))
                    {
                        objectControllers[principalKey].Add(new[] { "WriteAllProperties", pkiObject.DistinguishedName });
                    }
                }
            }

            foreach (var v in objectControllers)
            {
                if (v.Value.Count == 0) continue;

                var parts = v.Key.Split('\t');
                var userName = parts[0];
                var userSID = parts[1];
                var userString = userSID;

                if (hideAdmins &&
                    (userSID.EndsWith("-519") ||
                     userSID.EndsWith("-512") ||
                     (userSID == "S-1-5-32-544") ||
                     (userSID == "S-1-5-18"))
                )
                {
                    continue;
                }

                if (!String.IsNullOrEmpty(userName))
                {
                    userString = $"{userName} ({userSID})";
                }
                Console.WriteLine($"\n    {userString}");

                foreach (var entry in v.Value)
                {
                    // value -> (right, DN) tuple
                    var right = (System.String[])entry;
                    Console.WriteLine($"        {right[0],-18} {right[1]}");
                }
            }
        }

        public static void PrintCertificateInfo(X509Certificate2 ca)
        {
            Console.WriteLine($"    Cert SubjectName              : {ca.SubjectName.Name}");
            Console.WriteLine($"    Cert Thumbprint               : {ca.Thumbprint}");
            Console.WriteLine($"    Cert Serial                   : {ca.SerialNumber}");
            Console.WriteLine($"    Cert Start Date               : {ca.NotBefore}");
            Console.WriteLine($"    Cert End Date                 : {ca.NotAfter}");

            var chain = new X509Chain();
            chain.Build(ca);
            var names = new List<string>();
            foreach (var elem in chain.ChainElements)
            {
                names.Add(elem.Certificate.SubjectName.Name.Replace(" ", ""));
            }

            names.Reverse();
            Console.WriteLine("    Cert Chain                    : {0}", String.Join(" -> ", names));
        }

        public static string GetUserSidString(string sid, int padding = 30)
        {
            var user = "<UNKNOWN>";

            try
            {
                var sidObj = new SecurityIdentifier(sid);
                user = sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return $"{user}".PadRight(padding) + $"{sid}";
        }

        public static string GetUserNameFromSid(string sid)
        {
            var user = "";

            try
            {
                var sidObj = new SecurityIdentifier(sid);
                user = sidObj.Translate(typeof(NTAccount)).ToString();
            }
            catch
            {
            }

            return user;
        }

        public static string GetSanString(bool userSpecifiesSanEnabled, string? errorMessage)
        {
            string userSuppliedSanStr;

            if (errorMessage == null)
            {
                userSuppliedSanStr = userSpecifiesSanEnabled
                    ? "[!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!"
                    : "UserSpecifiedSAN              : Disabled";
            }
            else
            {
                userSuppliedSanStr = $"UserSpecifiedSAN              : {errorMessage}";
            }

            return userSuppliedSanStr;
        }

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

        public static string? GetDomainFromDN(string dn)
        {
            var index = dn.IndexOf("DC=");
            if(index == -1)
            {
                return null;
            }

            try 
            {
                return dn.Substring(index + 3, dn.Length - index - 3).Replace(",DC=", ".");
            }
            catch
            {
                return null;
            }
        }
    }
}
