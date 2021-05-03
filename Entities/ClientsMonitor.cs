using System;

namespace Cyber20ShadowServer.Entities
{
    public class ClientsMonitor
    {
        public int ServerID { get; set; }
        public DateTime TimeStamp { get; set; }
        public string ClientIP { get; set; }
        public string ClientMAC { get; set; }
        public string LogedInUser { get; set; }
        public string ClientStatus { get; set; }
        public string CertificateStatus { get; set; }
        public string WhiteListVersion { get; set; }
        public string ConnectionStatus { get; set; }
        public string UIVersion { get; set; }
        public string DriverVersion { get; set; }
        public string ClientOSVersion { get; set; }
        public string LogSenderVersion { get; set; }
        public string SUPVersion { get; set; }
        public string ServiceVersion { get; set; }
        public string ReconnaissanceVersion { get; set; }
        public int IsScrambled { get; set; }
        public string LastWhiteListDataInsert { get; set; }
        public string ClientDescription { get; set; }
        public string ClientGroup { get; set; }
        public string ClientName { get; set; }
    }
}