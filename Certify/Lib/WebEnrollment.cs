using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

#if !DISARMED

namespace Certify.Lib
{
    public class WebEnrollResult
    {
        public bool Success { get; set; }
        public string Certificate { get; set; }
        public int RequestId { get; set; }
        public string StatusMessage { get; set; }
    }

    class WebEnrollment
    {
        public static WebEnrollResult SubmitRequest(string caHost, string csrBase64, string templateName, bool useHttps = false)
        {
            var result = new WebEnrollResult();
            var scheme = useHttps ? "https" : "http";
            var submitUrl = $"{scheme}://{caHost}/certsrv/certfnsh.asp";

            try
            {
                var certAttrib = "CertificateTemplate:" + templateName;
                var postData = "Mode=newreq&CertRequest="
                    + Uri.EscapeDataString(csrBase64)
                    + "&CertAttrib=" + Uri.EscapeDataString(certAttrib)
                    + "&TargetStoreFlags=0&SaveCert=yes&ThumbPrint=";

                var req = CreateRequest(submitUrl, useHttps);
                req.Method = "POST";
                req.ContentType = "application/x-www-form-urlencoded";

                var bodyBytes = Encoding.UTF8.GetBytes(postData);
                req.ContentLength = bodyBytes.Length;
                using (var s = req.GetRequestStream())
                    s.Write(bodyBytes, 0, bodyBytes.Length);

                string responseHtml;
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var sr = new StreamReader(resp.GetResponseStream()))
                    responseHtml = sr.ReadToEnd();

                var m = Regex.Match(responseHtml, @"certnew\.cer\?ReqID=(\d+)");
                if (!m.Success)
                {
                    result.Success = false;

                    if (responseHtml.Contains("Access is denied"))
                    {
                        result.StatusMessage = "Access denied by the CA.";
                    }
                    else if (responseHtml.Contains("Pending"))
                    {
                        result.StatusMessage = "The certificate is still pending.";
                        var pending = Regex.Match(responseHtml, @"Your Request Id is (\d+)");
                        if (pending.Success)
                            result.RequestId = int.Parse(pending.Groups[1].Value);
                    }
                    else
                    {
                        var em = Regex.Match(responseHtml, @"Disposition\s*message[^>]*>\s*([^<]+)");
                        result.StatusMessage = em.Success
                            ? em.Groups[1].Value.Trim()
                            : "The submission failed with an unknown error.";
                    }

                    return result;
                }

                result.RequestId = int.Parse(m.Groups[1].Value);
                result.Success = true;
                result.StatusMessage = "The certificate has been issued.";
                result.Certificate = DownloadCert(caHost, result.RequestId, useHttps);
            }
            catch (WebException ex)
            {
                result.Success = false;
                result.StatusMessage = $"HTTP error: {ex.Message}";

                if (ex.Response != null)
                {
                    try
                    {
                        using (var sr = new StreamReader(ex.Response.GetResponseStream()))
                        {
                            var body = sr.ReadToEnd();
                            if (body.Length > 500) body = body.Substring(0, 500);
                            result.StatusMessage += "\n" + body;
                        }
                    }
                    catch { }
                }
            }

            return result;
        }

        public static string DownloadCert(string caHost, int requestId, bool useHttps = false)
        {
            var scheme = useHttps ? "https" : "http";
            var certUrl = $"{scheme}://{caHost}/certsrv/certnew.cer?ReqID={requestId}&Enc=b64";

            var req = CreateRequest(certUrl, useHttps);
            req.Method = "GET";

            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var sr = new StreamReader(resp.GetResponseStream()))
                return sr.ReadToEnd();
        }

        private static HttpWebRequest CreateRequest(string url, bool useHttps)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
            req.Timeout = 30000;
            req.ReadWriteTimeout = 30000;
            req.UseDefaultCredentials = true;

            if (useHttps)
                ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;

            return req;
        }
    }
}

#endif
