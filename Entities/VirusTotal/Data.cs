using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cyber20ShadowServer.Entities.VirusTotal
{
    public class Data
    {
        [JsonProperty("attributes")]
        public FileResult Attributes { get; set; }
        public string Type { get; set; }
        [JsonProperty("id")]
        public string ID { get; set; }
        public Link Links { get; set; }
    }
}
