//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Cyber20ShadowServer
{
    using System;
    using System.Collections.Generic;
    
    public partial class OriginTable
    {
        public int ID { get; set; }
        public Nullable<int> ServerID { get; set; }
        public string ApplicationName { get; set; }
        public string ApplicationVersion { get; set; }
        public string Status { get; set; }
        public Nullable<byte> NumOfEnginesDetected { get; set; }
        public string ComputerName { get; set; }
        public string ClientGroup { get; set; }
        public Nullable<System.DateTime> RequestTime { get; set; }
        public string ApplicationMD5 { get; set; }
        public string ScanLinks { get; set; }
        public Nullable<System.DateTime> CreateDate { get; set; }
        public Nullable<bool> IsActive { get; set; }
    
        public virtual Server Server { get; set; }
    }
}
