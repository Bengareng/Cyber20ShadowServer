using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cyber20ShadowServer.Entities.VirusTotal
{
    public class SignaAnalysisStatus
    {
        public int High { get; set; }
        public int Medium { get; set; }
        public int Critical { get; set; }
        public int Low { get; set; }
    }
}
