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
    
    public partial class Group
    {
        public int ID { get; set; }
        public Nullable<int> ServerID { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public Nullable<int> License { get; set; }
        public Nullable<bool> IsActive { get; set; }
        public Nullable<System.DateTime> CreateDate { get; set; }
    
        public virtual Server Server { get; set; }
    }
}
