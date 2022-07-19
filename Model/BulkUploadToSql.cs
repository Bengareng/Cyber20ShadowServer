using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;

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

        /// <summary>
        /// SqlBulkCopy is allegedly protected from Sql Injection.
        /// Updates a list of simple sql objects that mock tables.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="rows">A list of rows to insert</param>
        /// <param name="tableName">a Table name if your class isn't your table name minus s.</param>
        /// <returns>bool success</returns>
        public bool BulkUpdateData()
        {
            string[] RemovedColumnMapping = { "Server", "ClientsMonitorOriginTables", "GroupUsers", "ClientsMonitor", "OriginTable" };

            var template = InternalStore.FirstOrDefault();
            string tn = TableName ?? template.GetType().Name + "s";
            int updated = 0;
            using (SqlConnection con = new SqlConnection(ConnectionString))
            {
                using (SqlCommand command = new SqlCommand("", con))
                {
                    using (SqlBulkCopy sbc = new SqlBulkCopy(con))
                    {
                        var dt = new DataTable();
                        var columns = template.GetType().GetProperties(); ;
                        var colNames = new List<string>();
                        string keyName = "";
                        var setStatement = new StringBuilder();
                        int rowNum = 0;
                        //var sdf = InternalStore.ToDataTable();
                        foreach (var row in InternalStore)
                        {
                            dt.Rows.Add();
                            int colNum = 0;
                            foreach (var col in columns)
                            {
                                var attributes = row.GetType().GetProperty(col.Name).GetCustomAttributes(false);
                                bool isPrimary = col.Name == "ID";//IsPrimaryKey(attributes);
                                var value = row.GetType().GetProperty(col.Name).GetValue(row);
                                if (RemovedColumnMapping.Contains(col.Name)) continue;
                                //if (Type.GetTypeCode(col.PropertyType) == TypeCode.Object) continue;

                                if (rowNum == 0)
                                {
                                    colNames.Add($"{col.Name} {GetSqlDataType(col.PropertyType, isPrimary)}");
                                    dt.Columns.Add(new DataColumn(col.Name, Nullable.GetUnderlyingType(col.PropertyType) ?? col.PropertyType));
                                    if (!isPrimary) setStatement.Append($" ME.{col.Name} = T.{col.Name},");
                                }

                                if (isPrimary)
                                {
                                    keyName = col.Name;
                                    if (value == null)
                                    {
                                        throw new Exception("Trying to update a row whose primary key is null; use insert instead.");
                                    }
                                }

                                dt.Rows[rowNum][colNum] = value ?? DBNull.Value;
                                colNum++;
                            }
                            rowNum++;
                        }
                        setStatement.Length--;
                        try
                        {
                            con.Open();

                            command.CommandText = $"CREATE TABLE [dbo].[#TmpTable]({String.Join(",", colNames)})";
                            //command.CommandTimeout = CmdTimeOut;
                            command.ExecuteNonQuery();

                            sbc.DestinationTableName = "[dbo].[#TmpTable]";
                            sbc.BulkCopyTimeout = 660;
                            sbc.WriteToServer(dt);
                            sbc.Close();

                            command.CommandTimeout = 660;
                            command.CommandText = $"UPDATE ME SET {setStatement} FROM {tn} as ME INNER JOIN #TmpTable AS T on ME.{keyName} = T.{keyName}; DROP TABLE #TmpTable;";
                            updated = command.ExecuteNonQuery();
                        }
                        catch (Exception ex)
                        {
                            if (con.State != ConnectionState.Closed)
                            {
                                sbc.Close();
                                con.Close();
                            }
                            //well logging to sql might not work... we could try... but no.
                            //So Lets write to a local file.

                            throw ex;
                        }

                    }
                }
            }

            return (updated > 0) ? true : false;
        }


        private string GetSqlDataType(Type type, bool isPrimary = false)
        {
            var sqlType = new StringBuilder();
            var isNullable = false;
            if (Nullable.GetUnderlyingType(type) != null)
            {
                isNullable = true;
                type = Nullable.GetUnderlyingType(type);
            }
            switch (Type.GetTypeCode(type))
            {
                case TypeCode.String:
                    isNullable = true;
                    sqlType.Append("nvarchar(MAX)");
                    break;
                case TypeCode.Int32:
                case TypeCode.Int64:
                case TypeCode.Int16:
                    sqlType.Append("int");
                    break;
                case TypeCode.Boolean:
                    sqlType.Append("bit");
                    break;
                case TypeCode.DateTime:
                    sqlType.Append("datetime");
                    break;
                case TypeCode.Decimal:
                case TypeCode.Double:
                    sqlType.Append("decimal");
                    break;
            }
            if (!isNullable || isPrimary)
            {
                sqlType.Append(" NOT NULL");
            }
            return sqlType.ToString();
        }

    }
}