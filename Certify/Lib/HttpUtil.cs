using System;
using System.Net;

namespace Certify.Lib
{
    class HttpUtil
    {
        public static bool UrlExists(string url, string authType = "Negotiate")
        {
            var request = WebRequest.Create(url);
            //request.UseDefaultCredentials = true;
            //request.Credentials = CredentialCache.DefaultCredentials;

            var credcache = new CredentialCache();
            credcache.Add(new Uri(url), authType, CredentialCache.DefaultNetworkCredentials);
            request.Credentials = credcache;

            request.Timeout = 3000;

            try
            {
                using var response = (HttpWebResponse)request.GetResponse();
                return response.StatusCode == HttpStatusCode.OK ||
                       response.StatusCode == HttpStatusCode.Unauthorized ||
                       response.StatusCode == HttpStatusCode.Forbidden;
            }
            catch (WebException ex)
            {
                // Check if the exception is due to Unauthorized (401) or Forbidden (403)
                if (ex.Response is HttpWebResponse errorResponse)
                {
                    return errorResponse.StatusCode == HttpStatusCode.Unauthorized ||
                           errorResponse.StatusCode == HttpStatusCode.Forbidden;
                }
            }

            // If there's an exception or the status code is not one of the expected ones, return false
            return false;
        }
    }
}
