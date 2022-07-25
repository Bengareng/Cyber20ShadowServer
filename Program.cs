using Cyber20ShadowServer.Entities.VirusTotal;
using Cyber20ShadowServer.Model;
using Cyber20ShadowServer.Model.Extension;
using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Entity;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Configuration;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;



namespace Cyber20ShadowServer
{
    internal class Program
    {
        static readonly Cyber20ShadowEntities db = new Cyber20ShadowEntities();
        static readonly SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(db.Database.Connection.ConnectionString);
        static readonly string virusTotalKey = ConfigurationManager.AppSettings["x-apikey"];

        //static readonly bool flag = true;
        private const int VirusTotalRequestRate = 1000;
        private static async Task Main(string[] args)
        {




            try
            {
                var SuspiciousAppNeedToReport = await Task.Run(() => OriginShadowConnection());

                if (SuspiciousAppNeedToReport.Any())
                {
                    var appsByGroups = SuspiciousAppNeedToReport.GroupBy(x => new { x.Server, x.ClientGroup }, (key, x) => x.FirstOrDefault()).ToList();

                    foreach (var item in appsByGroups)
                    {
                        string _getUser = "select U.Email from [User] U " +
                            "INNER JOIN GroupUser GU ON GU.UserID = U.ID " +
                            "INNER JOIN  [Group] G ON G.ID = GU.GroupID " +
                            $"WHERE G.Name = '{item.ClientGroup}' AND G.ServerID = {item.ServerID}";
                        var emails = db.Database.SqlQuery<string>(_getUser).ToArray();

                        if (emails.Any())
                        {
                            string ss = CreateFolderFileForExcel("Report", "EmailAlert") + $"\\Cyber 2.0-{item.ClientGroup}.csv";
                            var userSuspiciousApp = SuspiciousAppNeedToReport.Where(x => x.ServerID == item.ServerID && x.ClientGroup == item.ClientGroup);

                            userSuspiciousApp.Select(x => new { x.ApplicationName, x.ClientGroup, x.ApplicationMD5, x.ApplicationVersion, x.ComputerName, x.DisplayName, x.NumOfEnginesDetected, x.ScanLinks, x.Status, x.CreateDate }).WriteToCSV(ss);
                            if (SendMail(ss, emails, userSuspiciousApp))
                                File.Delete(ss);
                        }
                    }


                    string adminPath = CreateFolderFileForExcel("Report", "EmailAlert") + $"\\Cyber 2.0-Administroator.csv";

                    string q = "SELECT Email FROM [User] U " +
                         "INNER JOIN UserRole UR ON UR.UserID = U.ID " +
                         "INNER JOIN [Role] R ON R.ID = UR.RoleID " +
                         "WHERE r.Name = 'Administrator'";

                    SuspiciousAppNeedToReport.WriteToCSV(adminPath);

                    if (SendMail(adminPath, db.Database.SqlQuery<string>(q).ToArray(), SuspiciousAppNeedToReport))
                        File.Delete(adminPath);
                }




                //Task.Run( () =>  MatchCatgeoryAndOriginTable());

                //Task.Run(() => RunScannerUnScannerdApplicaiton(user));

            }
            catch (Exception ex)
            {
                WriteToFile(ex.Message + " - " + ex.StackTrace);
                Console.Write(ex.Message);
            }
        }

        //private static async Task RunScannerUnScannerdApplicaiton(User user)
        //{
        //    string curentTime = DateTime.Now.ToString("yyyy-MM-dd");
        //    string q = $"SELECT * FROM OriginTable WHERE CreateDate >= '{curentTime}' AND Status != 'Not Scanned Yet' ORDER BY ID DESC";
        //    //string q = $"SELECT * FROM OriginTable WHERE CreateDate >= '{curentTime}'";
        //    var data = db.Database.SqlQuery<OriginTable>(q).ToList();
        //    if (data.Count() < VirusTotalRequestRate)
        //        ScannAllUnScannedApplicaition(VirusTotalRequestRate - data.Count());

        //}
        private static IEnumerable<OriginTable> OriginShadowConnection()
        {
            List<Server> Server = new List<Server>();
            List<OriginTable> SuspiciousAppNeedToReport = new List<OriginTable>();
            IEnumerable<Server> AllServers = db.Servers.Where(x => x.IsActive == true).ToList();
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
                            GetClientMonitor(connectionString, server.ID);

                            Console.WriteLine(connectionString);
                            try
                            {
                                try
                                {
                                    var Internal = Task.Run(() => STR_Connection(connectionString, server));
                                    Internal.Wait();
                                    var InternalStore = Internal.Result;
                                    Console.WriteLine(InternalStore.Any());
                                    //AddLostApplicationOfGroup(InternalStore);
                                    //List<OriginTable> NeedToRemoved = new List<OriginTable>();

                                    if (InternalStore.Any())
                                    {
                                        IEnumerable<OriginTable> sevingTable = InternalStore;
                                        server.LastApplicationsTableID = InternalStore.OrderByDescending(x => x.ID).FirstOrDefault().ID;
                                        Console.WriteLine(server.LastApplicationsTableID);

                                        List<OriginTable> nelistNew = new List<OriginTable>();
                                        foreach (var item in InternalStore.GroupBy(x => x.ApplicationMD5, (key, x) => x.FirstOrDefault()))
                                        {
                                            var vm = db.OriginTables.FirstOrDefault(x => x.ApplicationMD5 == item.ApplicationMD5);
                                            if (vm == null)
                                                nelistNew.Add(item);
                                        }

                                        //if (nelistNew.Any()) InternalStore = nelistNew;

#if !DEBUG
                                        if (nelistNew.Any())
                                        {
                                            //string curentTime = DateTime.Now.ToString("yyyy-MM-dd");
                                            //string q = $"SELECT * FROM OriginTableUser WHERE CreateDate >= '{curentTime}' AND UserID = {user.ID} ";
                                            //var scannerByAdministrator = db.Database.SqlQuery<OriginTableUser>(q).ToList().Count();

                                            //var scannerByAdministrator = db.OriginTableUsers.Count(x => x.ID == user.ID && x.CreateDate.Value.Date == DateTime.Now.Date);
                                            if (!string.IsNullOrEmpty(virusTotalKey))
                                                nelistNew.Where(x=> x.Status == "Not Scanned Yet").ToList().ForEach(x =>
                                                {
                                                    x.ID = 0;
                                                    Data virusTotal = VirusTotalFileReport(x.ApplicationMD5).Data;
                                                    if (virusTotal != null)
                                                    {
                                                        if (virusTotal.Attributes.LastAnalysisStatus.Malicious > 0)
                                                        {
                                                            x.Status = "Suspicious";
                                                        }
                                                        else
                                                            x.Status = "OK";

                                                        x.NumOfEnginesDetected = (byte)virusTotal.Attributes.LastAnalysisStatus.Malicious;
                                                        x.ScanLinks = $"https://www.virustotal.com/gui/file/{virusTotal.ID}";
                                                    }
                                                    else x.Status = "Unknown";
                                                });

                                                SuspiciousAppNeedToReport.AddRange(nelistNew.Where(x => x.NumOfEnginesDetected > 2));
                                        }
#endif

                                        BulkUploadToSql<OriginTable> objBulk = new BulkUploadToSql<OriginTable>()
                                        {
                                            InternalStore = nelistNew,
                                            TableName = "OriginTable",
                                            CommitBatchSize = 1000,
                                            ConnectionString = $"Data Source={builder.DataSource}; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                                        };

                                        UpdateUnSceneOriginTable(nelistNew.Where(x => x.Status != "Not Scanned Yet").ToList());

                                        if (objBulk.Commit())
                                        {
                                            WriteToFile("objBulk.Commit()");

                                            string[] groups = InternalStore.GroupBy(x => x.ClientGroup).Select(x => x.Key).ToArray();

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
                                                    db.SaveChanges();
                                                }
                                            }

                                        }

                                        string q = $"SELECT  TOP({nelistNew.Count()}) * FROM OriginTable WHERE ApplicationMD5 IN('{string.Join("','", nelistNew.Select(x => x.ApplicationMD5))}')  ORDER BY ID DESC";
                                        var otu = db.Database.SqlQuery<OriginTable>(q).ToList();
                                        InsertClientsMonitorOriginTable(sevingTable, otu, server.ID);

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


            return SuspiciousAppNeedToReport;
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
                    //SqlCommand cmd = new SqlCommand(ReturnLostApplicationQuery((int)server.LastApplicationsTableID, "marrive"), conn);
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
            //query += $" WHERE   AT.RequestTime >= '2022-06-1' and AT.RequestTime <= '2022-07-1'AND ClientGroup  in ('Sarid') ORDER BY AT.RequestTime ";
            query += $" WHERE  AT.RequestTime >= '2022-06-1' AND AT.ID > {lastID} ORDER BY AT.RequestTime ";

            return query;

        }


        static void GetClientMonitor(string serverConnectionString, int serverID)
        {
            IEnumerable<ClientsMonitor> NewClientsMonitros = null;
            IEnumerable<ClientsMonitor> TempOfAllClientsMonitors = null;
            var _clientsMonitor = Task.Run(() =>
            {
                var _clintsMonitorList = Cyber20DB_Connection(serverConnectionString, serverID).ToList();
                NewClientsMonitros = _clintsMonitorList.Where(x => x.ID == 0).ToList();
                TempOfAllClientsMonitors = _clintsMonitorList.Where(x => x.ID != 0).ToList();
            });
            _clientsMonitor.Wait();



            if (NewClientsMonitros.Any())
                _ = new BulkUploadToSql<ClientsMonitor>()
                {
                    InternalStore = NewClientsMonitros,
                    TableName = "ClientsMonitor",
                    CommitBatchSize = 1000,
                    //ConnectionString = $"Data Source={builder.DataSource}; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                    ConnectionString = db.Database.Connection.ConnectionString.ToString()
                }.Commit();

            if (TempOfAllClientsMonitors.Any())
                _ = new BulkUploadToSql<ClientsMonitor>()
                {
                    InternalStore = TempOfAllClientsMonitors,
                    TableName = "ClientsMonitor",
                    CommitBatchSize = 1000,
                    //ConnectionString = $"Data Source={builder.DataSource}; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                    ConnectionString = db.Database.Connection.ConnectionString.ToString()
                }.BulkUpdateData();
        }

        static string SqlQueryGetClinetGroups()
        {
            string query = "SELECT * FROM [Cyber20DB].[dbo].[ClientsGroups]";
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
                    sw.WriteLine($"[{DateTime.Now}] - {Message}");
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
            //Cyber20ShadowEntities db = new Cyber20ShadowEntities();

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
                            ConnectionString = $"Data Source={builder.DataSource}; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
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
                    query += "SELECT * FROM [Cyber20DB].[dbo].[ClientsMonitor] " +
                        "WHERE TIMESTAMP >= DATEADD(day,-2, getdate()) " +
                        "ORDER BY TIMESTAMP DESC;";
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
                                ClientName = rdr["ClientName"].ToString(),
                                ClientIP = rdr["ClientIP"].ToString(),
                                ClientMAC = rdr["ClientMAC"].ToString(),
                                GUID = rdr["GUID"].ToString(),
                                LogedInUser = rdr["LogedInUser"].ToString(),
                                ClientStatus = rdr["ClientStatus"].ToString(),
                                CertificateStatus = rdr["CertificateStatus"].ToString(),
                                CurrentPublicKey = rdr["CurrentPublicKey"].ToString(),
                                WhiteListVersion = rdr["WhiteListVersion"].ToString(),
                                ConnectionStatus = rdr["ConnectionStatus"].ToString(),
                                UniqueID = rdr["UniqueID"].ToString(),
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
                                IsScrambledRequired = int.Parse(rdr["IsScrambledRequired"].ToString()),
                                LastCertificateUpdate = rdr["LastCertificateUpdate"].ToString(),
                                LastWhiteListUpdate = rdr["LastWhiteListUpdate"].ToString(),
                                CreateDate = DateTime.Now


                            };


                            var _clientMonitor = db.ClientsMonitors.FirstOrDefault(f => f.UniqueID == ClientsMonitor.UniqueID);
                            if (_clientMonitor != null) ClientsMonitor.ID = _clientMonitor.ID;

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
            //Cyber20ShadowEntities db = new Cyber20ShadowEntities();

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
        static void InsertClientsMonitorOriginTable(IEnumerable<OriginTable> sevingTable, IEnumerable<OriginTable> newServer, int serverID)
        {
            //Cyber20ShadowEntities db = new Cyber20ShadowEntities();
            List<OriginTable> _ot = new List<OriginTable>();
            List<ClientsMonitorOriginTable> clientsMonitorOriginTables = new List<ClientsMonitorOriginTable>();
            sevingTable.ToList().ForEach(x =>
            {
                OriginTable data = newServer.FirstOrDefault(s => s.ApplicationMD5 == x.ApplicationMD5);
                if (data != null)
                    x = data;
                else
                {
                    data = db.OriginTables.FirstOrDefault(s => s.ApplicationMD5 == x.ApplicationMD5);
                    if (data != null)
                        x.ID = data.ID;
                }

                var sdf = db.ClientsMonitors.FirstOrDefault(cm => cm.ClientGroup == x.ClientGroup && cm.ClientName == x.ComputerName && cm.ConnectionStatus == "Online");
                if (sdf != null) clientsMonitorOriginTables.Add(new ClientsMonitorOriginTable { OriginTableID = data.ID, ClientsMonitorID = sdf.ID, CreateDate = DateTime.Now, RequestTime = x.RequestTime });
                else _ot.Add(x);

            });


            if (clientsMonitorOriginTables.Any())
            {
                WriteToFile($"ClientsMonitorOriginTable => {clientsMonitorOriginTables.Any()}");
                BulkUploadToSql<ClientsMonitorOriginTable> objBulkcmot = new BulkUploadToSql<ClientsMonitorOriginTable>()
                {
                    InternalStore = clientsMonitorOriginTables,
                    TableName = "ClientsMonitorOriginTable",
                    CommitBatchSize = 1000,
                    ConnectionString = $"Data Source={builder.DataSource}; Initial Catalog=Cyber20Shadow; User ID=sa; Password=Cyber@123;"
                };
                objBulkcmot.Commit();
            }
        }
        static VirusTotal VirusTotalFileReport(string md5)
        {
            var client = new RestClient($"https://www.virustotal.com/api/v3/files/{md5}");
            var request = new RestRequest(Method.GET);
            request.AddHeader("Accept", "application/json");
            request.AddHeader("x-apikey", virusTotalKey);
            //request.AddHeader("x-apikey", "297fa1d048dca19fc1003bcfbd601c79f1ef78ec090fd4b9019923beb16d68c2");
            IRestResponse response = client.Execute(request);
            return JsonConvert.DeserializeObject<VirusTotal>(response.Content);
        }
        static void ScannAllUnScannedApplicaition(int size)
        {
            //Cyber20ShadowEntities db = new Cyber20ShadowEntities();

            //var ot = db.OriginTables.OrderByDescending(x => x.RequestTime).Where(x => x.Status == "Not Scanned Yet").Take(size).ToList();

            string q = $"SELECT  TOP({size}) * FROM OriginTable WHERE Status != 'Not Scanned Yet' ORDER BY ID DESC";
            var ot = db.Database.SqlQuery<OriginTable>(q).ToList();
            WriteToFile($"{ot.Count()}");
            if (ot.Any())
            {
                ot.ForEach(x =>
                {
                    Data virusTotal = VirusTotalFileReport(x.ApplicationMD5).Data;
                    if (virusTotal != null)
                    {
                        if (virusTotal.Attributes.LastAnalysisStatus.Malicious > 0) x.Status = "Suspicious";
                        else x.Status = "OK";

                        x.NumOfEnginesDetected = (byte)virusTotal.Attributes.LastAnalysisStatus.Malicious;
                        x.ScanLinks = $"https://www.virustotal.com/gui/file/{virusTotal.ID}";
                    }
                    else x.Status = "Unknown";
                });

                WriteToFile($"SaveChanges - < ScannAllUnScannedApplicaition");

                db.SaveChanges();
            }
        }
        private static string CreateFolderFileForExcel(string folderName, string nestedFolder)
        {
            string path = $"C:\\{folderName}";
            string nestedFolderpath = $"{path}\\{nestedFolder}";

            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            if (!Directory.Exists(nestedFolderpath))
            {
                Directory.CreateDirectory(nestedFolderpath);
            }
            return nestedFolderpath;
        }
        static IEnumerable<OriginTable> AddLostApplicationOfGroup(IEnumerable<OriginTable> InternalStore)
        {
            var test = (from ot in db.OriginTables
                        join cmot in db.ClientsMonitorOriginTables
                        on ot.ID equals cmot.OriginTableID
                        join cm in db.ClientsMonitors
                        on cmot.ClientsMonitorID equals cm.ID
                        where cm.ClientGroup == "marrive"
                        select new { ot, cm }

                        //new OriginTable
                        //{
                        //    ApplicationMD5 = ot.ApplicationName,
                        //    Status = ot.Status,
                        //    ServerID = ot.ServerID,
                        //    ScanLinks = ot.ScanLinks,
                        //    RequestTime = ot.RequestTime,
                        //    ProcessPath = ot.ProcessPath,
                        //    NumOfEnginesDetected = ot.NumOfEnginesDetected,
                        //    InWhitelist = ot.InWhitelist,
                        //    ApplicationName = ot.ApplicationName,
                        //    ApplicationVersion = ot.ApplicationVersion,
                        //    ClientGroup = cm.ClientGroup,
                        //    ComputerName = cm.ClientName,
                        //    CreateDate = DateTime.Now,
                        //    IsActive = true,
                        //    DisplayName = ot.DisplayName
                        //}
                        ).ToList().Select(x =>
                            new OriginTable
                            {
                                ApplicationMD5 = x.ot.ApplicationMD5,
                                Status = x.ot.Status,
                                ServerID = x.ot.ServerID,
                                ScanLinks = x.ot.ScanLinks,
                                RequestTime = x.ot.RequestTime,
                                ProcessPath = x.ot.ProcessPath,
                                NumOfEnginesDetected = x.ot.NumOfEnginesDetected,
                                InWhitelist = x.ot.InWhitelist,
                                ApplicationName = x.ot.ApplicationName,
                                ApplicationVersion = x.ot.ApplicationVersion,
                                ClientGroup = x.cm.ClientGroup,
                                ComputerName = x.cm.ClientName,
                                //CreateDate = DateTime.Now,
                                IsActive = true,
                                DisplayName = x.ot.DisplayName
                            }
                        ).ToList();




            return InternalStore.Where(x => !test.Where(s => s.ApplicationMD5 == x.ApplicationMD5 && s.ComputerName == x.ComputerName).Any()).ToList();
        }
        static bool SendMail(string path, string[] emails, IEnumerable<OriginTable> InternalStore)
        {

            if (path != "")
            {
                SmtpSection section = (SmtpSection)ConfigurationManager.GetSection("system.net/mailSettings/smtp");

                using (MailMessage Msg = new MailMessage())
                {
                    foreach (var email in emails)
                    {
                        Msg.To.Add(new MailAddress(email, "Report", Encoding.UTF8));
                    }

                    Msg.Subject = "Cyber 2.0 Alert info - " + DateTime.Now.Date.ToString();
                    Msg.Attachments.Add(new Attachment(path, "application/vnd.ms-excel"));
                    //Msg.From = new MailAddress("cyber@cyber20.com");
                    Msg.IsBodyHtml = true;
                    Msg.Body = TableTemplateHtml(InternalStore);
                    SmtpClient smtp = new SmtpClient
                    {
                        Host = section.Network.Host,
                        EnableSsl = section.Network.EnableSsl,
                        DeliveryMethod = SmtpDeliveryMethod.Network,
                        DeliveryFormat = SmtpDeliveryFormat.International,
                        UseDefaultCredentials = false,
                        Port = section.Network.Port,
                        Timeout = 10000,
                        Credentials = new NetworkCredential(section.Network.UserName, section.Network.Password)
                    };
                    try
                    {
                        smtp.Send(Msg);
                        return true;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message + " - " + ex.StackTrace + " - " + ex.Source + " - " + ex.GetType());
                        return false;
                    }
                }
            }
            return false;
        }
        static string ReturnLostApplicationQuery(int lastID, string group)
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
            query += $" WHERE AT.ID < {lastID} " +
                $"AND cm.ClientGroup = '{group}'" +
                $"ORDER BY AT.RequestTime ";

            return query;

        }


        static string TableTemplateHtml(IEnumerable<object> originTables)
        {

            StringBuilder sb = new StringBuilder();

            sb.Append("<!DOCTYPE html>");
            sb.Append("<html dir='rtl'><body>");

            //sb.Append("Hi " + username + ",<br/><br/> " + "Alignment Details <br/>");
            sb.Append(@"<table border='1' cellpadding='0' cellspacing='0' height='100%' width='100%' >");
            sb.Append("<tr>" +
                "<th>ApplicationName</th>" +
                "<th>ClientGroup</th>" +
                "<th>ApplicationMD5</th>" +
                "<th>ApplicationVersion</th>" +
                "<th>ComputerName</th>" +
                "<th>DisplayName</th>" +
                "<th>NumOfEnginesDetected</th>" +
                "<th>ScanLinks</th>" +
                "<th>Status</th>" +
                "<th>CreateDate</th>" +
                "</tr>");
            foreach (OriginTable origin in originTables)
            {
                string color = origin.NumOfEnginesDetected > 9 ? "red" : "orange";
                sb.Append("<tr color='red'>");
                sb.Append($"<td><font color='{color}'>{origin.ApplicationName}</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.ClientGroup}</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.ApplicationMD5}</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.ApplicationVersion  }</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.ComputerName}</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.DisplayName}</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.NumOfEnginesDetected}</font></td>");
                sb.Append($"<td><a href={origin.ScanLinks} color='{color}'>Link</a></td>");
                sb.Append($"<td><font color='{color}'>{origin.Status}</font></td>");
                sb.Append($"<td><font color='{color}'>{origin.CreateDate}</font></td>");
                sb.Append($"</tr>");
            }
            sb.Append("</table><br/> Regards, <br/>Web Master.");
            sb.Append("</body></html>");

            return sb.ToString();
        }
    }
}