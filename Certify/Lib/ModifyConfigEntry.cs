using System;
using System.ServiceProcess;

namespace Certify.Lib
{
    class ModifyConfigEntry
    {

        // change the CA configuration
        public static void ModifyEntry(string CA, bool enableSAN = false, bool removeApproval = false, bool restart = false)
        {

            Console.WriteLine($"\r\n[*] Certificate Authority   : {CA}");

            CERTADMINLib.ICertAdmin2 objCertAdmin = new CERTADMINLib.CCertAdmin();

            try
            {

                if (enableSAN)
                {
                    // read the current configuration 
                    var entry = objCertAdmin.GetConfigEntry(CA, @"PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags");

                    // 0x00040000 ==  EDITF_ATTRIBUTESUBJECTALTNAME2 
                    if (((int)entry & 0x00040000) == 0x00040000)
                    {
                        Console.WriteLine("\r\n[*] EDITF_ATTRIBUTESUBJECTALTNAME2 is already enabled. No changes required.");
                    }
                    else
                    {
                        // flip the EDITF_ATTRIBUTESUBJECTALTNAME2 bit
                        var newValue = (int)entry | 0x00040000;
                        objCertAdmin.SetConfigEntry(CA, @"PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", newValue);
                        Console.WriteLine("\r\n[*] EDITF_ATTRIBUTESUBJECTALTNAME2 enabled!");
                    }


                }

                if (removeApproval)
                {
                    // read the current configuration 
                    var entry = objCertAdmin.GetConfigEntry(CA, @"PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "RequestDisposition");

                    // 0x00000100 ==  REQDISP_PENDINGFIRST
                    if (((int)entry & 0x00000100) == 0)
                    {
                        Console.WriteLine("\r\n[*] The CA is not forcing the approval of requested certificates. No changes required.");
                    }
                    else
                    {
                        // Edit the registry entry RequestDisposition to remove the required approval for requested certificates
                        var newValue = (int)entry & 0x11111011;
                        objCertAdmin.SetConfigEntry(CA, @"PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "RequestDisposition", newValue);
                        Console.WriteLine("\r\n[*] Approval for requested certificates is no longer required.");

                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error changing CA's configuration: {e}");
                return;
            }

            // in the vast majority of circunstances it is required to restart the CA service
            if (restart)
            {
                restartCA(CA);
            }
        }

        public static void restartCA(string CA)
        {
            var computerName = CA.Replace("\\\\", "\\");
            computerName = computerName.Split('\\')[0];

            ServiceController sc = new ServiceController("CertSvc", computerName);

            try
            {
                if (sc.Status == ServiceControllerStatus.Running)
                {
                    sc.Stop();
                    sc.WaitForStatus(ServiceControllerStatus.Stopped);
                }

                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running);
               
                Console.WriteLine("\r\n[*] CertSvc service restarted!");

            }
            catch (Exception e)
            {
                Console.WriteLine($"[X] Error restarting CA service (CertSvc): {e}");
                return;
            }
            finally
            {
                sc.Close();
            }
        }
    }
}
