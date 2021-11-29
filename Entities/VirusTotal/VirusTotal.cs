using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cyber20ShadowServer.Entities.VirusTotal
{
    public class VirusTotal
    {
        [JsonProperty("data")]
        public Data Data { get; set; }
    }
}
