rule Certify
{
    meta:
        description = "The TypeLibGUID present in a .NET binary maps directly to the ProjectGuid found in the '.csproj' file of a .NET project."
        author = "Will Schroeder (@harmj0y)"
    strings:
        $typelibguid = "15cfadd8-5f6c-424b-81dc-c028312d025f" ascii nocase wide
    condition:
        uint16(0) == 0x5A4D and $typelibguid
}