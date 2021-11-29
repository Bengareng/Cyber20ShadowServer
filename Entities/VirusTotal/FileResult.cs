using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cyber20ShadowServer.Entities.VirusTotal
{
    public class FileResult
    {
        [JsonProperty("type_description")]
        public string TypeDescription { get; set; }

        public string Tlsh { get; set; }
        //[JsonProperty("creation_date")]
        //public int CreationDate { get; set; }
        public string[] Names { get; set; }
        [JsonProperty("type_tag")]
        public string TypeTag { get; set; }
        [JsonProperty("times_submitted")]
        public int TimesSubmitted { get; set; }
        public int Size { get; set; }
        [JsonProperty("type_extension")]
        public string TypeExtension { get; set; }
        public string Authentihash { get; set; }

        [JsonProperty("last_submission_date")]
        public int LastSubmissionDate { get; set; }
        [JsonProperty("meaningful_name")]
        public string MeaningfulName { get; set; }
        public bool Downloadable { get; set; }
        public string Sha256 { get; set; }
        public string[] Tags { get; set; }
        [JsonProperty("last_analysis_date")]
        public int LastAnalysisDate { get; set; }
        [JsonProperty("first_submission_date")]
        public int FirstSubmissionDate { get; set; }
        [JsonProperty("unique_sources")]
        public int UniqueSources { get; set; }
        public string Sha1 { get; set; }
        public string Ssdeep { get; set; }
        public string MD5 { get; set; }
        public string Magic { get; set; }
        [JsonProperty("first_seen_itw_date")]
        public int FirstSeenItwDate { get; set; }
        public int Reputation { get; set; }
        [JsonProperty("sigma_analysis_stats")]
        public SignaAnalysisStatus SignaAnalysisStatus { get; set; }

        [JsonProperty("last_analysis_stats")]
        public LastAnalysisStatus LastAnalysisStatus { get; set; }
    }

}
