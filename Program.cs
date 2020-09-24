using Cyber20ShadowServer.Model;
using Cyber20ShadowServer.Repository;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;


namespace Cyber20ShadowServer
{
    class Program
    {

        static void Main(string[] args)
        {
            OriginShadowConnection();
        }


        static IEnumerable<Server> OriginShadowConnection()
        {
            GenericRepository<Server> _serverRepository = new GenericRepository<Server>();
            List<Server> Server = new List<Server>();
            foreach (Server server in _serverRepository.GetAll())
            {
                if ((bool)server.IsActive)
                {
                    server.NextRetentionTime = server.NextRetentionTime ?? DateTime.Now;
                    if (server.NextRetentionTime.Value <= DateTime.Now)
                    {
                        string connectionString = $"Data Source={server.IPAddress}; Initial Catalog=Cyber20CyberAnalyzerDB; User ID={server.UserName}; Password={server.Password}";
                        using (SqlConnection conn = new SqlConnection(connectionString))
                        {
                            SqlCommand cmd = new SqlCommand("GetAllCyberAnalyzerByLastID", conn)
                            {
                                CommandType = CommandType.StoredProcedure
                            };
                            cmd.Parameters.Add(new SqlParameter("@LastID", server.LastApplicationsTableID ?? 0));
                            List<OriginTable> InternalStore = new List<OriginTable>();
                            try
                            {
                                conn.Open();
                                using (SqlDataReader rdr = cmd.ExecuteReader())
                                {
                                    int LastApplicationsTableID = 0;
                                    while (rdr.Read())
                                    {
                                        OriginTable bbb = new OriginTable
                                        {
                                            ServerID = server.ID,
                                            ApplicationName = rdr["ApplicationName"].ToString(),
                                            ApplicationVersion = rdr["ApplicationVersion"].ToString(),
                                            Status = rdr["Status"].ToString(),
                                            ComputerName = rdr["ComputerName"].ToString(),
                                            ClientGroup = rdr["ClientGroup"].ToString(),
                                            RequestTime = DateTime.Parse(rdr["RequestTime"].ToString()),
                                            ApplicationMD5 = rdr["ApplicationMD5"].ToString(),
                                            ScanLinks = rdr["ScanLinks"].ToString()
                                        };
                                        if (rdr["NumOfEnginesDetected"].ToString() != "")
                                            bbb.NumOfEnginesDetected = byte.Parse(rdr["NumOfEnginesDetected"].ToString());
                                        else bbb.NumOfEnginesDetected = 0;
                                        LastApplicationsTableID = int.Parse(rdr["ID"].ToString());
                                        InternalStore.Add(bbb);
                                    }
                                    rdr.Close();
                                    if (InternalStore.Any())
                                    {
                                        BulkUploadToSql<OriginTable> objBulk = new BulkUploadToSql<OriginTable>()
                                        {
                                            InternalStore = InternalStore,
                                            TableName = "OriginTable",
                                            CommitBatchSize = 1000,
                                            ConnectionString = $"Data Source=localhost; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123"
                                        };
                                        if (objBulk.Commit())
                                            Server.Add(server);
                                    }
                                    server.LastConnection = server.NextRetentionTime;
                                    server.NextRetentionTime = DateTime.Now.AddMinutes(server.RetentionTime ?? 0);
                                    if (LastApplicationsTableID > (int)server.LastApplicationsTableID)
                                    {
                                        server.LastApplicationsTableID = LastApplicationsTableID;
                                    }
                                    _serverRepository.Update(server);
                                    _serverRepository.Save();
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                            }
                            conn.Close();
                        }
                    }
                }
            }

            return Server;
        }



    }
}
