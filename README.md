# Certify

Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).

[@harmj0y](https://twitter.com/harmj0y) and [@tifkin_](https://twitter.com/tifkin_) are the primary authors of Certify and the the associated AD CS research ([blog](https://posts.specterops.io/certified-pre-owned-d95910965cd2) and [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)).

## Table of Contents
- [Certify](#certify)
  - [Usage](#usage)
  - [Defensive Considerations](#defensive-considerations)
  - [Compile Instructions](#compile-instructions)
    - [Sidenote: Running Certify Through PowerShell](#sidenote-running-certify-through-powershell)
      - [Sidenote Sidenote: Running Certify Over PSRemoting](#sidenote-sidenote-running-certify-over-psremoting)
  - [Reflections](#reflections)
  - [Acknowledgments](#acknowledgments)


## Usage

A command overview and comprehensive usage details can be found on the [wiki](https://github.com/GhostPack/Certify/wiki).

## Defensive Considerations

Certify was released at Black Hat 2021 with our ["Certified Pre-Owned: Abusing Active Directory Certificate Services"](https://www.blackhat.com/us-21/briefings/schedule/#certified-pre-owned-abusing-active-directory-certificate-services-23168) talk.

See our [whitepaper](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf) for prevention and detection guidance.


## Compile Instructions

We are not planning on releasing binaries for Certify, so you will have to compile yourself :)

Certify has been built against .NET 4.7.2 and is compatible with [Visual Studio 2022 Community Edition](https://visualstudio.microsoft.com/vs/community/). Simply open up the project .sln, choose "Release", and build.


### Sidenote: Running Certify Through PowerShell

If you want to run Certify in-memory through a PowerShell wrapper, first compile the Certify and base64-encode the resulting assembly:

    [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\Certify.exe")) | Out-File -Encoding ASCII C:\Temp\Certify.txt

Certify can then be loaded in a PowerShell script with the following (where "aa..." is replaced with the base64-encoded Certify assembly string):

    $CertifyAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String("aa..."))

The Main() method and any arguments can then be invoked as follows:

    [Certify.Program]::Main("enum-templates --filter-enabled --filter-vulnerable".Split())


#### Sidenote Sidenote: Running Certify Over PSRemoting

Due to the way PSRemoting handles output, we need to redirect stdout to a string and return that instead. Luckily, Certify has a function to help with that.

If you follow the instructions in [Sidenote: Running Certify Through PowerShell](#sidenote-running-Certify-through-powershell) to create a Certify.ps1, append something like the following to the script:

    [Certify.Program]::MainString("enum-templates --filter-enabled --filter-vulnerable")

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

