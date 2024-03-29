﻿//------------------------------------------------------------------------------
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
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    using System.Data.Entity.Core.Objects;
    using System.Linq;
    
    public partial class Cyber20ShadowEntities : DbContext
    {
        public Cyber20ShadowEntities()
            : base("name=Cyber20ShadowEntities")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<Category> Categories { get; set; }
        public virtual DbSet<ClientsMonitor> ClientsMonitors { get; set; }
        public virtual DbSet<ClientsMonitorOriginTable> ClientsMonitorOriginTables { get; set; }
        public virtual DbSet<Group> Groups { get; set; }
        public virtual DbSet<OriginTable> OriginTables { get; set; }
        public virtual DbSet<OriginTableCategory> OriginTableCategories { get; set; }
        public virtual DbSet<OriginTableUser> OriginTableUsers { get; set; }
        public virtual DbSet<Server> Servers { get; set; }
        public virtual DbSet<User> Users { get; set; }
    
        public virtual ObjectResult<QueryListWiteOutDuplicatedRows_Result> QueryListWiteOutDuplicatedRows()
        {
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<QueryListWiteOutDuplicatedRows_Result>("QueryListWiteOutDuplicatedRows");
        }
    
        public virtual ObjectResult<QueryListWiteOutDuplicatedRowsTest_Result> QueryListWiteOutDuplicatedRowsTest()
        {
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<QueryListWiteOutDuplicatedRowsTest_Result>("QueryListWiteOutDuplicatedRowsTest");
        }
    }
}
