using Cyber20ShadowServer.Entities.VirusTotal;
using Cyber20ShadowServer.Model;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Threading.Tasks;



namespace Cyber20ShadowServer
{
    internal class Program
    {
        private const int VirusTotalRequestRate = 1000;
        private static void Main(string[] args)
        {
            Cyber20ShadowEntities db = new Cyber20ShadowEntities();
            try
            {


                var user = db.Users.FirstOrDefault(x => x.Email == "cyber@cyber20.com");
                OriginShadowConnection(user);

                MatchCatgeoryAndOriginTable();

                if (DateTime.Now.Hour == 23 && user != null)
                {
                    string curentTime = DateTime.Now.ToString("yyyy-MM-dd");
                    string q = $"SELECT * FROM OriginTableUser WHERE CreateDate >= '{curentTime}' AND UserID = {user.ID} ";
                    //string q = $"SELECT * FROM OriginTable WHERE CreateDate >= '{curentTime}'";
                    var data = db.Database.SqlQuery<OriginTableUser>(q).ToList();
                    if (data.Count() < VirusTotalRequestRate)
                        ScannAllUnScannedApplicaition(VirusTotalRequestRate - data.Count());
                }

            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message + " - " + ex.StackTrace);
                Console.Write(ex.Message);
            }
        }

        private static IEnumerable<Server> OriginShadowConnection(User user)
        {
            Cyber20ShadowEntities db = new Cyber20ShadowEntities();


            List<Server> Server = new List<Server>();
            IEnumerable<Server> AllServers = db.Servers.Where(x => x.IsActive == true).AsNoTracking().ToList();
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

                                    if (InternalStore.Any())
                                    {
                                        IEnumerable<OriginTable> sevingTable = InternalStore;
                                        server.LastApplicationsTableID = InternalStore.OrderByDescending(x => x.ID).FirstOrDefault().ID;
                                        Console.WriteLine(server.LastApplicationsTableID);

                                        InternalStore = InternalStore.GroupBy(x => x.ApplicationMD5, (key, x) => x.FirstOrDefault())
                                            .Where(x => !db.OriginTables.Select(s => s.ApplicationMD5).Contains(x.ApplicationMD5)).ToList();

                                        if (user != null)
                                        {
                                            string curentTime = DateTime.Now.ToString("yyyy-MM-dd");
                                            string q = $"SELECT * FROM OriginTableUser WHERE CreateDate >= '{curentTime}' AND UserID = {user.ID} ";
                                            var scannerByAdministrator = db.Database.SqlQuery<OriginTableUser>(q).ToList().Count();

                                            //var scannerByAdministrator = db.OriginTableUsers.Count(x => x.ID == user.ID && x.CreateDate.Value.Date == DateTime.Now.Date);
                                            if (scannerByAdministrator < VirusTotalRequestRate)
                                                InternalStore.ToList().ForEach(x =>
                                                {
                                                    x.ID = 0;
                                                    Data virusTotal = VirusTotalFileReport(x.ApplicationMD5).Data;
                                                    if (virusTotal != null)
                                                    {
                                                        if (virusTotal.Attributes.LastAnalysisStatus.Malicious > 0)
                                                            x.Status = "Suspicious";
                                                        else
                                                            x.Status = "OK";

                                                        x.NumOfEnginesDetected = (byte)virusTotal.Attributes.LastAnalysisStatus.Malicious;
                                                        x.ScanLinks = $"https://www.virustotal.com/gui/file/{virusTotal.ID}";
                                                    }
                                                    else x.Status = "Unknown";
                                                });
                                        }

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
                                            WriteToFile("objBulk.Commit()");


                                            if (user != null)
                                            {
                                                var otu = db.OriginTables.OrderByDescending(x => x.ID).Take(InternalStore.Count()).ToList();



                                                var originTableUsers = otu.Select(x => new OriginTableUser
                                                {
                                                    CreateDate = DateTime.Now,
                                                    OriginTableID = x.ID,
                                                    UserID = user.ID
                                                }).ToList();

                                                var otuBulk = new BulkUploadToSql<OriginTableUser>()
                                                {
                                                    InternalStore = originTableUsers,
                                                    TableName = "OriginTableUser",
                                                    CommitBatchSize = 1000,
                                                    ConnectionString = $"Data Source=localhost; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                                                }.Commit();
                                            }

                                            string[] groups = InternalStore.OrderBy(x => x.ID).GroupBy(x => x.ClientGroup).Select(x => x.Key).ToArray();
                                            foreach (string g in groups)
                                            {
                                                if (!db.Groups.Where(x => x.Name == g).ToList().Any())
                                                {
                                                    db.Groups.Add(new Group
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

                                        InsertClientsMonitorOriginTable(sevingTable, server.ID);

                                        if (flag)
                                        {
                                            WriteToFile("Groups.cyber20ShadowEntities.SaveChanges()");
                                            db.SaveChanges();
                                        }
                                        Server.Add(server);
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

                                db.Servers.Attach(server);
                                db.Entry(server).State = EntityState.Modified;

                                db.SaveChanges();
                                WriteToFile("cyber20ShadowEntities.Servers.Attach(server)");
                            }
                            catch (Exception ex)
                            {
                                WriteToFile(ex.Message + " - " + ex.StackTrace + " - " + ex.Source + " - " + ex.GetType());
                            }
                        }              
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
                    cmd.CommandTimeout = 180;
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
   
        }
        private static void WriteToFile(string Message)
        {
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

            var lastItem = db.OriginTableCategories.OrderByDescending(x => x.OriginTableID).FirstOrDefault();
            //int lastId = 0;
            foreach (Category c in db.Categories.Where(x => x.ParentID > 0).ToList())
            {
                //if (lastItem != null) lastId = lastItem.OriginTableID;
                string query = $"SELECT * FROM [Cyber20Shadow].[dbo].[OriginTable]  OT " +
                    $"Left  JOIN [Cyber20Shadow].[dbo].[OriginTableCategories] OTC ON OTC.OriginTableID = OT.ID " +
                    $"WHERE ApplicationName LIKE '{c.Name.Replace("*", "%").Replace("_", "[_]").Replace("'", "''")}' AND OTC.OriginTableID IS NULL AND OT.ID > {(lastItem != null ? lastItem.ID : 0)}";

                try
                {
                    var originTableCategories = db.Database.SqlQuery<OriginTable>(query).Select(x => new OriginTableCategory { OriginTableID = x.ID, CategoryID = c.ID, CreateDate = DateTime.Now }).ToList();
                    if (originTableCategories.Any())
                    {
                        _ = new BulkUploadToSql<OriginTableCategory>()
                        {
                            InternalStore = originTableCategories,
                            TableName = "OriginTableCategories",
                            CommitBatchSize = 1000,
                            ConnectionString = $"Data Source=localhost; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                        }.Commit();
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
                    if (list.Count() > 0)
                    {
                        list.ForEach(x =>
                        {
                            x.Status = originTable.Status;
                            x.ScanLinks = originTable.ScanLinks;
                            x.NumOfEnginesDetected = originTable.NumOfEnginesDetected;
                            x.InWhitelist = originTable.InWhitelist;

                            db.Entry(x).State = EntityState.Modified;

                        });

                        db.SaveChanges();
                    }
                }
                return true;
            }

            return false;
        }

        static string QueryListWiteOutDuplicatedRows()
        {
            string q = "WITH cte AS ( SELECT [ServerID],[ApplicationName] ,[ApplicationVersion],[Status],[DisplayName],[InWhitelist],[NumOfEnginesDetected],[ComputerName]" +
                ",[ClientGroup],[RequestTime],[ApplicationMD5],[ScanLinks],[IsActive],[Remark],[ProcessPath]" +
                ",ROW_NUMBER() OVER (PARTITION BY " +
                " [ServerID],[ApplicationName] ,[ApplicationVersion],[Status],[DisplayName],[InWhitelist],[NumOfEnginesDetected],[ComputerName]" +
                ",[ClientGroup],[RequestTime],[ApplicationMD5],[ScanLinks],[IsActive],[Remark],[ProcessPath]" +
                " ORDER BY  [ServerID],[ApplicationName] ,[ApplicationVersion],[Status],[DisplayName],[InWhitelist],[NumOfEnginesDetected],[ComputerName] " +
                " ,[ClientGroup],[RequestTime],[ApplicationMD5],[ScanLinks],[IsActive],[Remark],[ProcessPath] ) row_num FROM [Cyber20Shadow].[dbo].[OriginTable])" +
                " SELECT * FROM cte WHERE row_num = 1";
            return q;

        }


        static void InsertClientsMonitorOriginTable(IEnumerable<OriginTable> sevingTable, int serverID)
        {
            Cyber20ShadowEntities db = new Cyber20ShadowEntities();

            var tables = (from ot in db.OriginTables.AsEnumerable()
                          join sot in sevingTable on ot.ApplicationMD5
                          equals sot.ApplicationMD5
                          select ot).GroupBy(x => x.ApplicationMD5, (index, value) => value.FirstOrDefault()).ToList();

            List<ClientsMonitorOriginTable> clientsMonitorOriginTables = new List<ClientsMonitorOriginTable>();
            //var lastInsert = db.OriginTables.OrderByDescending(s => new { s.CreateDate }).Take(InternalStore.Count()).ToList();
            foreach (var item in db.ClientsMonitors.Where(x => x.ServerID == serverID && x.ConnectionStatus == "Online"))
            {
                var sdf = sevingTable.Where(x => x.ClientGroup == item.ClientGroup && x.ComputerName == item.ClientName).Select(x => new ClientsMonitorOriginTable { OriginTableID = tables.FirstOrDefault(d => d.ApplicationMD5 == x.ApplicationMD5).ID, ClientsMonitorID = item.ID, CreateDate = DateTime.Now }).ToList();


                if (sdf.Any()) clientsMonitorOriginTables.AddRange(sdf);
            }

            if (clientsMonitorOriginTables.Any())
            {
                WriteToFile($"ClientsMonitorOriginTable => {clientsMonitorOriginTables.Any()}");
                BulkUploadToSql<ClientsMonitorOriginTable> objBulkcmot = new BulkUploadToSql<ClientsMonitorOriginTable>()
                {
                    InternalStore = clientsMonitorOriginTables,
                    TableName = "ClientsMonitorOriginTable",
                    CommitBatchSize = 1000,
                    ConnectionString = $"Data Source=localhost; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                };
                objBulkcmot.Commit();
            }
        }

        static VirusTotal VirusTotalFileReport(string md5)
        {
            var client = new RestClient($"https://www.virustotal.com/api/v3/files/{md5}");
            var request = new RestRequest(Method.GET);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("x-apikey", "297fa1d048dca19fc1003bcfbd601c79f1ef78ec090fd4b9019923beb16d68c2");
            IRestResponse response = client.Execute(request);
            return JsonConvert.DeserializeObject<VirusTotal>(response.Content);
        }


        static void ScannAllUnScannedApplicaition(int size)
        {
            Cyber20ShadowEntities db = new Cyber20ShadowEntities();

            var ot = db.OriginTables.Where(x => x.Status == "Not Scanned Yet").OrderByDescending(x => x.ID).Take(size).ToList();
            WriteToFile($"{ot.Count()}");
            if (ot.Any())
            {
                ot.ForEach(x =>
                {
                    Data virusTotal = VirusTotalFileReport(x.ApplicationMD5).Data;
                    if (virusTotal != null)
                    {
                        if (virusTotal.Attributes.LastAnalysisStatus.Malicious > 0)
                            x.Status = "Suspicious";
                        else
                            x.Status = "OK";

                        x.NumOfEnginesDetected = (byte)virusTotal.Attributes.LastAnalysisStatus.Malicious;
                        x.ScanLinks = $"https://www.virustotal.com/gui/file/{virusTotal.ID}";
                    }
                    else x.Status = "Unknown";
                });
                WriteToFile($"SaveChanges - < ScannAllUnScannedApplicaition");

                db.SaveChanges();
            }
        }
    }
}