using System;

namespace Certify
{
    public static class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine("\r\n   _____          _   _  __              ");
            Console.WriteLine("  / ____|        | | (_)/ _|             ");
            Console.WriteLine(" | |     ___ _ __| |_ _| |_ _   _        ");
            Console.WriteLine(" | |    / _ \\ '__| __| |  _| | | |      ");
            Console.WriteLine(" | |___|  __/ |  | |_| | | | |_| |       ");
            Console.WriteLine("  \\_____\\___|_|   \\__|_|_|  \\__, |   ");
            Console.WriteLine("                             __/ |       ");
            Console.WriteLine("                            |___./        ");
            Console.WriteLine("  v{0}                               \r\n", Certify.Version.version);
        }

        public static void ShowUsage()
        {
            var usage = @"
  Find information about all registered CAs:
    
    Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks] [/quiet]
  

  Find all enabled certificate templates:
    
    Certify.exe find [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find vulnerable/abusable certificate templates using default low-privileged groups:

    Certify.exe find /vulnerable [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find vulnerable/abusable certificate templates using all groups the current user context is a part of:

    Certify.exe find /vulnerable /currentuser [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find enabled certificate templates where ENROLLEE_SUPPLIES_SUBJECT is enabled:

    Certify.exe find /enrolleeSuppliesSubject [/ca:SERVER\ca-name| /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find enabled certificate templates capable of client authentication:

    Certify.exe find /clientauth [/ca:SERVER\ca-name | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

  Find all enabled certificate templates, display all of their permissions, and don't display the banner message:
    
    Certify.exe find /showAllPermissions /quiet [/ca:COMPUTER\CA_NAME | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local]

  Find all enabled certificate templates and output to a json file:
    
    Certify.exe find /json /outfile:C:\Temp\out.json [/ca:COMPUTER\CA_NAME | /domain:domain.local | /ldapserver:server.domain.local | /path:CN=Configuration,DC=domain,DC=local]


  Enumerate access control information for PKI objects:

    Certify.exe pkiobjects [/domain:domain.local | /ldapserver:server.domain.local] [/showAdmins] [/quiet]


  Request a new certificate using the current user context:

    Certify.exe request /ca:SERVER\ca-name [/subject:X] [/template:Y] [/install]

  Request a new certificate using the current machine context:

    Certify.exe request /ca:SERVER\ca-name /machine [/subject:X] [/template:Y] [/install]

  Request a new certificate using the current user context but for an alternate name (if supported):

    Certify.exe request /ca:SERVER\ca-name /template:Y /altname:USER

  Request a new certificate using the current user context but for an alternate name and SID (if supported):

    Certify.exe request /ca:SERVER\ca-name /template:Y /altname:USER /sid:S-1-5-21-2697957641-2271029196-387917394-2136

  Request a new certificate using the current user context but for an alternate name and URL (if supported):

    Certify.exe request /ca:SERVER\ca-name /template:Y /altname:USER /url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-2697957641-2271029196-387917394-2136

  Request a new certificate on behalf of another user, using an enrollment agent certificate:
    
    Certify.exe request /ca:SERVER\ca-name /template:Y /onbehalfof:DOMAIN\USER /enrollcert:C:\Temp\enroll.pfx [/enrollcertpw:CERT_PASSWORD]


  Download an already requested certificate:

    Certify.exe download /ca:SERVER\ca-name /id:X [/install] [/machine]
";
            Console.WriteLine(usage);
        }
    }
}
