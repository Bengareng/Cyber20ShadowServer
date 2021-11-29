using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cyber20ShadowServer.Entities.VirusTotal
{
    public class LastAnalysisStatus
    {
        public int Harmless { get; set; }
        [JsonProperty("type-unsupported")]
        public int TypeUnsupported { get; set; }
        public int Suspicious { get; set; }
        [JsonProperty("confirmed-timeout")]
        public int ConfirmedTimeout { get; set; }
        public int Timeout { get; set; }
        public int Failure { get; set; }
        public int Malicious { get; set; }
        public int Undetected { get; set; }
    }
}
