namespace Certify.Lib
{
    class LdapSearchOptions
    {
        public LdapSearchOptions()
        {
            Domain = null;
            //AuthenticationType = null;
            //Credential = null;
        }
        public string? Domain { get; set; }
        //public AuthenticationTypes? AuthenticationType { get; set; }
        //public NetworkCredential? Credential { get; set; }
    }
}
