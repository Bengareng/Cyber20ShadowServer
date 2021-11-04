using Cyber20ShadowServer.Entities;
using Cyber20ShadowServer.Model;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.SqlClient;
using System.IO;
using System.Linq;

namespace Cyber20ShadowServer
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                OriginShadowConnection();

                MatchCatgeoryAndOriginTable();
            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message + " - " + ex.StackTrace);
                Console.Write(ex.Message);
            }
        }

        private static IEnumerable<Server> OriginShadowConnection()
        {
            Cyber20ShadowEntities cyber20ShadowEntities = new Cyber20ShadowEntities();

            List<Server> Server = new List<Server>();
            IEnumerable<Server> AllServers = cyber20ShadowEntities.Servers.Where(x => x.IsActive == true).AsNoTracking().ToList();
            if (AllServers.Any())
            {
                foreach (Server server in AllServers)
                {
                    Console.WriteLine(server.IPAddress);
                    string connectionString = "";
                    if ((bool)server.IsActive)
                    {
                        if (server.NextRetentionTime.Value <= DateTime.Now)
                        {
                            connectionString = $"Data Source={server.IPAddress}; Initial Catalog=Cyber20CyberAnalyzerDB; User ID={server.UserName}; Password={server.Password};";

                            Console.WriteLine(connectionString);

                            try
                            {
                                try
                                {
                                    IEnumerable<OriginTable> InternalStore = STR_Connection(connectionString, server).ToList();
                                    Console.WriteLine(InternalStore.Any());
                                    List<OriginTable> NeedToRemoved = new List<OriginTable>();
                                    //var sdf = InternalStore.Where(x => x.ServerID == null).ToList();
                                    if (InternalStore.Any())
                                    {

                                        server.LastApplicationsTableID = InternalStore.OrderByDescending(x => x.ID).FirstOrDefault().ID;
                                        Console.WriteLine(server.LastApplicationsTableID);
                                        //cyber20ShadowEntities.BulkInsert(InternalStore);

                                        BulkUploadToSql<OriginTable> objBulk = new BulkUploadToSql<OriginTable>()
                                        {
                                            InternalStore = InternalStore,
                                            TableName = "OriginTable",
                                            CommitBatchSize = 1000,
                                            ConnectionString = $"Data Source=localhost; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                                        };

                                        bool flag = false;
                                        UpdateUnSceneOriginTable(InternalStore.Where(x => x.Status != "Not Scanned Yet").ToList());
                                        if (objBulk.Commit())
                                        {
                                            //cyber20ShadowEntities.BulkSaveChanges();
                                            WriteToFile("objBulk.Commit()");
                                            string[] groups = InternalStore.OrderBy(x => x.ID).GroupBy(x => x.ClientGroup).Select(x => x.Key).ToArray();
                                            foreach (string g in groups)
                                            {
                                                if (!cyber20ShadowEntities.Groups.Where(x => x.Name == g).ToList().Any())
                                                {
                                                    cyber20ShadowEntities.Groups.Add(new Group
                                                    {
                                                        IsActive = true,
                                                        CreateDate = DateTime.Now,
                                                        Name = g.Trim(),
                                                        ServerID = server.ID
                                                    });
                                                    flag = true;
                                                }
                                            }
                                        }


                                        if (flag)
                                        {
                                            WriteToFile("Groups.cyber20ShadowEntities.SaveChanges()");
                                            cyber20ShadowEntities.SaveChanges();
                                        }
                                        Server.Add(server);

                                        //}
                                    }
                                }
                                catch (Exception ex)
                                {
                                    WriteToFile(ex.Message + " - " + ex.StackTrace + " - " + ex.Source + " - " + ex.GetType());
                                    throw;
                                }

                                server.LastConnection = server.NextRetentionTime;
                                server.NextRetentionTime = DateTime.Now.AddMinutes(server.RetentionTime ?? 0);

                                Console.WriteLine(server.NextRetentionTime);

                                cyber20ShadowEntities.Servers.Attach(server);
                                cyber20ShadowEntities.Entry(server).State = EntityState.Modified;

                                cyber20ShadowEntities.SaveChanges();
                                WriteToFile("cyber20ShadowEntities.Servers.Attach(server)");
                            }
                            catch (Exception ex)
                            {
                                WriteToFile(ex.Message + " - " + ex.StackTrace + " - " + ex.Source + " - " + ex.GetType());
                            }
                        }

                        //connectionString = $"Data Source={server.IPAddress}; Initial Catalog=Cyber20DB; User ID={server.UserName}; Password={server.Password};";

                        //int lastInsert = cyber20ShadowEntities.Database.SqlQuery<int>($"SELECT COUNT(*) FROM ClientsMonitor WHERE ServerID = {server.ID}").Count();
                        //var ClientsMonitor = Cyber20DB_Connection(connectionString, server.ID).Skip(lastInsert).ToList();

                        //if (ClientsMonitor.Any())
                        //{
                        //    BulkUploadToSql<ClientsMonitor> objBulk = new BulkUploadToSql<ClientsMonitor>()
                        //    {
                        //        InternalStore = ClientsMonitor,
                        //        TableName = "ClientsMonitor",
                        //        CommitBatchSize = 1000,
                        //        ConnectionString = $"Data Source=localhost; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                        //    };
                        //    if (objBulk.Commit())
                        //    {
                        //        WriteToFile("ClientsMonitor is inserted");
                        //    }
                        //}
                    }
                }
            }


            return Server;
        }
        private static List<OriginTable> STR_Connection(string connectionString, Server server)
        {
            List<OriginTable> InternalStore = new List<OriginTable>();
            try
            {
                using (SqlConnection conn = new SqlConnection(connectionString))
                {
                    conn.Open();

                    // 1.  create a command object identifying the stored procedure
                    SqlCommand cmd = new SqlCommand(SqlQuery((int)server.LastApplicationsTableID), conn);

                    //// 2. set the command object so it knows to execute a stored procedure
                    //cmd.CommandType = CommandType.StoredProcedure;

                    //// 3. add parameter to command, which will be passed to the stored procedure
                    //cmd.Parameters.Add(new SqlParameter("@LastID", lastID));

                    // execute the command
                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        // iterate through results, printing each to console
                        while (rdr.Read())
                        {
                            OriginTable bbb = new OriginTable
                            {
                                ServerID = server.ID,
                                ApplicationName = rdr["ApplicationName"].ToString(),
                                ApplicationVersion = rdr["ApplicationVersion"].ToString(),
                                Status = rdr["Status"].ToString(),
                                ComputerName = rdr["ComputerName"].ToString(),
                                DisplayName = rdr["DisplayName"].ToString(),
                                ClientGroup = rdr["ClientGroup"].ToString(),
                                RequestTime = DateTime.Parse(rdr["RequestTime"].ToString()),
                                ApplicationMD5 = rdr["ApplicationMD5"].ToString(),
                                ScanLinks = rdr["ScanLinks"].ToString(),
                                ID = int.Parse(rdr["ID"].ToString()),
                                CreateDate = DateTime.Now,
                                IsActive = true
                            };
                            if (rdr["NumOfEnginesDetected"] != DBNull.Value)
                                bbb.NumOfEnginesDetected = byte.Parse(rdr["NumOfEnginesDetected"].ToString());
                            else bbb.NumOfEnginesDetected = 0;

                            if (rdr["InWhitelist"] != DBNull.Value)
                                bbb.InWhitelist = rdr["InWhitelist"].ToString();
                            else bbb.InWhitelist = "";


                            //server.LastApplicationsTableID = int.Parse(rdr["ID"].ToString());
                            InternalStore.Add(bbb);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message + " - " + ex.StackTrace + " - " + ex.Source + " - " + ex.GetType());

                throw;
            }
            return InternalStore;
        }
        private static string SqlQuery(int lastID)
        {
            string query = "SELECT DISTINCT" +
                " AT.ID ," +
                " AT.ApplicationName," +
                " AT.DisplayName," +
                " AT.ApplicationVersion," +
                " AT.Status," +
                " AT.NumOfEnginesDetected," +
                " CM.ClientName 'ComputerName'," +
                " CM.ClientGroup," +
                " AT.RequestTime," +
                " AT.InWhitelist," +
                " AT.ApplicationMD5," +
                " AT.ScanLinks ";

            query += "FROM  [Cyber20CyberAnalyzerDB].[dbo].[ApplicationsTable] AT ";
            query += "INNER JOIN [Cyber20CyberAnalyzerDB].[dbo].[ApplicationsComputersTable] ACT ON AT.ID = ACT.Application ";
            query += "INNER JOIN [Cyber20CyberAnalyzerDB].[dbo].[ComputersTable] CT ON ACT.Computer = CT.UID ";
            query += "INNER JOIN [Cyber20DB].[dbo].[ClientsMonitor] CM on CT.ComputerMAC = CM.ClientMAC AND CM.ClientName = CT.ComputerName";
            query += $" WHERE AT.ID > {lastID} ORDER BY AT.RequestTime ";

            return query;
            //return "SELECT DISTINCT" +
            //    " AT.ID ," +
            //    " AT.ApplicationName," +
            //    " AT.DisplayName," +
            //    " AT.ApplicationVersion," +
            //    " AT.Status," +
            //    " AT.NumOfEnginesDetected," +
            //    " CM.ClientName 'ComputerName'," +
            //    " CM.ClientGroup," +
            //    " AT.RequestTime," +
            //    " AT.InWhitelist," +
            //    " AT.ApplicationMD5," +
            //    " AT.ScanLinks" +
            //    " FROM ApplicationsComputersTable ACT " +
            //    " INNER JOIN ComputersTable CT ON   ACT.Computer = CT.UID" +
            //    " INNER JOIN ApplicationsTable AT ON AT.ID = ACT.Application" +
            //    " INNER JOIN [Cyber20DB].[dbo].[ClientsMonitor] CM ON CT.ComputerMAC = CM.ClientMAC" +
            //    $" WHERE AT.ID > {lastID} ORDER BY AT.RequestTime ";
        }
        private static void WriteToFile(string Message)
        {
            //string path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
            //if (!Directory.Exists(path))
            //{
            //    Directory.CreateDirectory(path);
            //}
            string filepath = AppDomain.CurrentDomain.BaseDirectory + "\\ServiceLog_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
            if (!System.IO.File.Exists(filepath))
            {
                FileInfo fi = new FileInfo(filepath);
                if (DateTime.Now.AddDays(-7).Date < fi.CreationTime)
                {
                    System.IO.File.Delete(filepath);
                }
                // Create a file to write to.
                using (StreamWriter sw = System.IO.File.CreateText(filepath))
                {
                    sw.WriteLine($"[{DateTime.Now.ToString()}] - {Message}");
                }
            }
            else
            {
                using (StreamWriter sw = System.IO.File.AppendText(filepath))
                {
                    sw.WriteLine($"[{DateTime.Now.ToString()}] - {Message}");
                }
            }
        }
        private static void MatchCatgeoryAndOriginTable()
        {
            Cyber20ShadowEntities db = new Cyber20ShadowEntities();

            //var lastItem = db.OriginTableCategories.OrderByDescending(x => x.OriginTableID).FirstOrDefault();
            //int lastId = 0;
            foreach (Category c in db.Categories.Where(x => x.ParentID > 0).ToList())
            {
                //if (lastItem != null) lastId = lastItem.OriginTableID;
                string query = $"SELECT * FROM [Cyber20Shadow].[dbo].[OriginTable]  OT " +
                    $"Left  JOIN [Cyber20Shadow].[dbo].[OriginTableCategories] OTC ON OTC.OriginTableID = OT.ID " +
                    $"WHERE ApplicationName LIKE '{c.Name.Replace("*", "%").Replace("_", "[_]").Replace("'", "''")}' AND OTC.OriginTableID IS NULL ";

                try
                {
                    var originTableCategories = db.Database.SqlQuery<OriginTable>(query).Select(x => new OriginTableCategory { OriginTableID = x.ID, CategoryID = c.ID, CreateDate = DateTime.Now }).ToList();
                    if (originTableCategories.Any())
                    {
                        db.OriginTableCategories.AddRange(originTableCategories);
                        db.SaveChanges();
                    }
                }
                catch (Exception)
                {

                    WriteToFile(query);

                    throw;
                }
            }
        }
        private static List<ClientsMonitor> Cyber20DB_Connection(string connectionString, int serverID)
        {
            List<ClientsMonitor> InternalStore = new List<ClientsMonitor>();
            try
            {
                using (SqlConnection conn = new SqlConnection(connectionString))
                {
                    conn.Open();
                    string query = "";
                    //query += "DBCC CHECKIDENT ('[TestTable]', RESEED, 0); ";
                    query += "SELECT * FROM [Cyber20DB].[dbo].[ClientsMonitor] ORDER BY TIMESTAMP DESC;";
                    // 1.  create a command object identifying the stored procedure
                    SqlCommand cmd = new SqlCommand(query, conn);

                    //// 2. set the command object so it knows to execute a stored procedure
                    //cmd.CommandType = CommandType.StoredProcedure;

                    //// 3. add parameter to command, which will be passed to the stored procedure
                    //cmd.Parameters.Add(new SqlParameter("@LastID", lastID));

                    // execute the command
                    using (SqlDataReader rdr = cmd.ExecuteReader())
                    {
                        // iterate through results, printing each to console
                        while (rdr.Read())
                        {
                            var ClientsMonitor = new ClientsMonitor
                            {
                                ServerID = serverID,
                                TimeStamp = DateTime.Parse(rdr["TimeStamp"].ToString()),
                                ClientIP = rdr["ClientIP"].ToString(),
                                ClientMAC = rdr["ClientMAC"].ToString(),
                                LogedInUser = rdr["LogedInUser"].ToString(),
                                ClientStatus = rdr["ClientStatus"].ToString(),
                                CertificateStatus = rdr["CertificateStatus"].ToString(),
                                WhiteListVersion = rdr["WhiteListVersion"].ToString(),
                                ConnectionStatus = rdr["ConnectionStatus"].ToString(),
                                UIVersion = rdr["UIVersion"].ToString(),
                                DriverVersion = rdr["DriverVersion"].ToString(),
                                ClientOSVersion = rdr["ClientOSVersion"].ToString(),
                                LogSenderVersion = rdr["LogSenderVersion"].ToString(),
                                SUPVersion = rdr["SUPVersion"].ToString(),
                                ServiceVersion = rdr["ServiceVersion"].ToString(),
                                ReconnaissanceVersion = rdr["ReconnaissanceVersion"].ToString(),
                                IsScrambled = int.Parse(rdr["IsScrambled"].ToString()),
                                LastWhiteListDataInsert = rdr["LastWhiteListDataInsert"].ToString(),
                                ClientDescription = rdr["ClientDescription"].ToString(),
                                ClientGroup = rdr["ClientGroup"].ToString(),
                                ClientName = rdr["ClientName"].ToString()
                            };

                            InternalStore.Add(ClientsMonitor);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message + " - " + ex.StackTrace + " - " + ex.Source + " - " + ex.GetType());

                throw;
            }
            return InternalStore;
        }
        private static bool UpdateUnSceneOriginTable(IEnumerable<OriginTable> InternalStore)
        {
            Cyber20ShadowEntities db = new Cyber20ShadowEntities();

            if (InternalStore.Any())
            {

                foreach (var originTable in InternalStore)
                {
                    var list = db.OriginTables.Where(x => x.ApplicationMD5 == originTable.ApplicationMD5 && originTable.RequestTime >= x.RequestTime && (x.Status != originTable.Status || x.ScanLinks != originTable.ScanLinks)).ToList();

                    if (list.Count() > 1)
                    {
                        list.ForEach(x =>
                        {
                            x.Status = originTable.Status;
                            x.ScanLinks = originTable.ScanLinks;
                            x.NumOfEnginesDetected = originTable.NumOfEnginesDetected;
                            x.InWhitelist = originTable.InWhitelist;
                        });
                        //table.Status = originTable.Status;
                        //table.ScanLinks = originTable.ScanLinks;
                        //table.NumOfEnginesDetected = originTable.NumOfEnginesDetected;
                        //table.InWhitelist = originTable.InWhitelist;
                        //db.OriginTables.Attach(table);
                        //db.Entry(table).State = EntityState.Modified;
                        db.SaveChanges();
                    }
                }
                return true;
            }

            return false;
        }
    }
}