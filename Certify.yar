rule Certify
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
        author = "Will Schroeder (@harmj0y)"
    strings:
        $typelibguid = "64524ca5-e4d0-41b3-acc3-3bdbefd40c97" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}