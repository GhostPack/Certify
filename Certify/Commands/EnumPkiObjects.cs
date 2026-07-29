using Certify.Domain;
using Certify.Lib;
using CommandLine;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security;
using System.Security.Principal;

namespace Certify.Commands
{
    internal class EnumPkiObjects
    {
        [Verb("enum-pkiobjects", HelpText = "Enumerate access controls for PKI objects")]
        public class Options : DefaultOptions
        {
            [Option("domain", HelpText = "Target domain (format: FQDN)")]
            public string Domain { get; set; }

            [Option("ldap-server", HelpText = "Target LDAP server")]
            public string LdapServer { get; set; }

            [Option("show-linked-oids", HelpText = "Show enterprise OIDs linked to groups")]
            public bool ShowLinkedOids { get; set; }

            [Option("show-admins", HelpText = "Include admin permissions")]
            public bool ShowAdmins { get; set; }
            
            [Option('u', "username", HelpText = "Username for LDAP bind (format: user@domain.fqdn). Omit to bind as the current user.")]
            public string Username { get; set; }

            [Option('p', "password", HelpText = "Password for LDAP bind. If omitted while --username is set, you'll be prompted (input hidden).")]
            public string Password { get; set; }
        }

        public static int Execute(Options opts)
        {
            Console.WriteLine("[*] Action: Find PKI object controllers");

            if (!string.IsNullOrEmpty(opts.Domain) && !opts.Domain.Contains('.'))
            {
                Console.WriteLine("[X] The 'domain' parameter is not a fully qualified domain name.");
                return 1;
            }

            if (!string.IsNullOrEmpty(opts.Username) && string.IsNullOrEmpty(opts.Password))
            {
                opts.Password = ReadPasswordMasked($"Password for {opts.Username}: ");
            }

            var ldap = new LdapOperations(opts.Domain, opts.LdapServer, opts.Username, opts.Password);

            Console.WriteLine($"[*] Using the search base '{ldap.ConfigurationPath}'");

            var pki_objects = ldap.GetPKIObjects();
            var object_controllers = GetPkiObjectControllers(pki_objects);

            Console.WriteLine();
            Console.WriteLine("[*] PKI Object Controllers:");
            DisplayUtil.PrintPkiObjectControllers(object_controllers, !opts.ShowAdmins);

            if (opts.ShowLinkedOids)
            {
                var oids = ldap.GetEnterpriseOids().Where(o => o.GroupLink != null);

                if (oids == null || !oids.Any())
                    Console.WriteLine("[*] There are no group-linked enterprise OIDs.");
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("[*] Group-linked Enterprise OIDs:");
                    
                    foreach (var oid in oids)
                    {
                        Console.WriteLine();
                        Console.WriteLine($"Oid          :  {oid.Oid.Value}");
                        Console.WriteLine($"Display Name :  {oid.DisplayName}");
                        Console.WriteLine($"Linked Group :  {oid.GroupLink}");
                    }
                }
            }

            return 0;
        }
        
        private static string ReadPasswordMasked(string prompt)
        {
            Console.Write(prompt);

            var secure = new SecureString();

            ConsoleKeyInfo key;
            while ((key = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
            {
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (secure.Length > 0)
                    {
                        secure.RemoveAt(secure.Length - 1);
                        Console.Write("\b \b");
                    }
                    continue;
                }

                if (key.KeyChar != '\0')
                {
                    secure.AppendChar(key.KeyChar);
                    Console.Write('*');
                }
            }

            Console.WriteLine();
            secure.MakeReadOnly();

            var ptr = System.Runtime.InteropServices.Marshal.SecureStringToGlobalAllocUnicode(secure);
            try
            {
                return System.Runtime.InteropServices.Marshal.PtrToStringUni(ptr);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        private static Dictionary<string, List<Tuple<string, string>>> GetPkiObjectControllers(IEnumerable<PKIObject> pki_objects)
        {
            var object_controllers = new Dictionary<string, List<Tuple<string, string>>>();

            foreach (var pki_object in pki_objects)
            {
                if (pki_object.SecurityDescriptor != null)
                {
                    var owner_sid = pki_object.SecurityDescriptor.GetOwner(typeof(SecurityIdentifier)).ToString();

                    if (!object_controllers.ContainsKey(owner_sid))
                        object_controllers[owner_sid] = new List<Tuple<string, string>>();

                    object_controllers[owner_sid].Add(new Tuple<string, string>("Owner", pki_object.DistinguishedName));

                    foreach (ActiveDirectoryAccessRule ace in pki_object.SecurityDescriptor.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    {
                        var principal_sid = ace.IdentityReference.ToString();

                        if (!object_controllers.ContainsKey(principal_sid))
                            object_controllers[principal_sid] = new List<Tuple<string, string>>();

                        if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.GenericAll))
                            object_controllers[principal_sid].Add(new Tuple<string, string>("GenericAll", pki_object.DistinguishedName));
                        else if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteOwner))
                            object_controllers[principal_sid].Add(new Tuple<string, string>("WriteOwner", pki_object.DistinguishedName));
                        else if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteDacl))
                            object_controllers[principal_sid].Add(new Tuple<string, string>("WriteDacl", pki_object.DistinguishedName));
                        else if (ace.ActiveDirectoryRights.HasFlag(ActiveDirectoryRights.WriteProperty) && $"{ace.ObjectType}" == "00000000-0000-0000-0000-000000000000")
                            object_controllers[principal_sid].Add(new Tuple<string, string>("WriteAllProperties", pki_object.DistinguishedName));
                    }
                }
            }

            return object_controllers;
        }
    }
}
