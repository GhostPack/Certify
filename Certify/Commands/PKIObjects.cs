using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Security.Principal;
using Certify.Domain;
using Certify.Lib;

namespace Certify.Commands
{
    public class PKIObjects : ICommand
    {
        public static string CommandName => "pkiobjects";
        private LdapOperations _ldap = new LdapOperations();
        private bool hideAdmins;
        private string? domain;
        private string? ldapServer;

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("[*] Action: Find PKI object controllers");

            hideAdmins = !arguments.ContainsKey("/showAdmins");

            if (arguments.ContainsKey("/domain"))
            {
                domain = arguments["/domain"];
                if (!domain.Contains("."))
                {
                    Console.WriteLine("[!] /domain:X must be a FQDN");
                    return;
                }
            }

            if (arguments.ContainsKey("/ldapserver"))
            {
                ldapServer = arguments["/ldapserver"];
            }

            _ldap = new LdapOperations(new LdapSearchOptions()
            {
                Domain = domain, LdapServer = ldapServer
            });

            Console.WriteLine($"[*] Using the search base '{_ldap.ConfigurationPath}'");

            DisplayPKIObjectControllers();
        }

        private void DisplayPKIObjectControllers()
        {
            Console.WriteLine("\n[*] PKI Object Controllers:");
            var pkiObjects = _ldap.GetPKIObjects();
            
            DisplayUtil.PrintPKIObjectControllers(pkiObjects, hideAdmins);
        }
    }
}
