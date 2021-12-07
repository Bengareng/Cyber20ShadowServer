using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;

namespace Cyber20ShadowServer.Model
{
    public class BulkUploadToSql<T>
    {
        public IEnumerable<T> InternalStore { get; set; }
        public string TableName { get; set; }
        public int CommitBatchSize { get; set; } = 1000;
        public string ConnectionString { get; set; }

        public bool Commit()
        {
            if (InternalStore.Count() > 0)
            {
                DataTable dt;
                int numberOfPages = (InternalStore.Count() / CommitBatchSize) + (InternalStore.Count() % CommitBatchSize == 0 ? 0 : 1);
                for (int pageIndex = 0; pageIndex < numberOfPages; pageIndex++)
                {
                    dt = InternalStore.Skip(pageIndex * CommitBatchSize).Take(CommitBatchSize).ToDataTable();
                    BulkInsert(dt);
                }
                return true;
            }
            return false;
        }

        public void BulkInsert(DataTable dt)
        {
            try
            {
                string[] tables = { "Server", "OriginTableCategories", "ClientsMonitorOriginTables", "OriginTable", "ClientsMonitor", "Category", "OriginTableUsers", "User" };
                using (SqlConnection connection = new SqlConnection(ConnectionString))
                {
                    SqlBulkCopy bulkCopy =
                        new SqlBulkCopy
                        (
                            connection,
                            SqlBulkCopyOptions.TableLock |
                            SqlBulkCopyOptions.FireTriggers |
                            SqlBulkCopyOptions.UseInternalTransaction,
                            null
                        );

                    foreach (DataColumn col in dt.Columns)
                    {

                        if (!tables.Contains(col.ColumnName))
                        {
                            bulkCopy.ColumnMappings.Add(col.ColumnName, col.ColumnName);
                        }
                    }
                    bulkCopy.DestinationTableName = TableName;
                    connection.Open();
                    bulkCopy.WriteToServer(dt);
                    connection.Close();
                }
                // reset
                //this.dataTable.Clear();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}