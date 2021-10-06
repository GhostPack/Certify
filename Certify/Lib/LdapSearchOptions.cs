namespace Certify.Lib
{
    class LdapSearchOptions
    {
        public LdapSearchOptions()
        {
            Domain = null;
            LdapServer = null;
            //AuthenticationType = null;
            //Credential = null;
        }
        public string? Domain { get; set; }
        public string? LdapServer { get; set; }
        //public AuthenticationTypes? AuthenticationType { get; set; }
        //public NetworkCredential? Credential { get; set; }
    }
}
