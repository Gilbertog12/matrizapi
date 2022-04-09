using Oracle.ManagedDataAccess.Client;
using System;
using System.Collections.Generic;
using System.Web.Configuration;

namespace MatrizRiesgos.Util
{
    public class ConnectionOracleImpl : IConnection
    {
        // Constantes
        private OracleConnection sqlConn;
        private OracleCommand sqlComm;
        public Boolean debugErrors = false;
        public Boolean debugWarnings = false;
        public Boolean debugQuerys = false;

        public ConnectionOracleImpl()
        {
        }

        public bool ConnectDB()
        {
            try
            {
                sqlConn = new OracleConnection(GetConnectionString());
                sqlConn.Open();
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        public string GetConnectionString()
        {
            try
            {
                string dbHost = WebConfigurationManager.AppSettings["DBHOST"];
                string dbPort = WebConfigurationManager.AppSettings["DBPORT"];
                string dbServiceName = WebConfigurationManager.AppSettings["DBSERVICENAME"];
                string dbUsername = WebConfigurationManager.AppSettings["DBUSERNAME"];
                string dbPassword = WebConfigurationManager.AppSettings["DBPASSWORD"];
                string connectionstring = "Data Source = (DESCRIPTION = (ADDRESS = (PROTOCOL = TCP)(HOST = " + dbHost + ")(PORT = " + dbPort + "))(CONNECT_DATA = (SERVICE_NAME = " + dbServiceName + "))); User Id = " + dbUsername + "; Password = " + dbPassword;

                return connectionstring;
            }
            catch (Exception)
            {
                return "";
            }
        }

        public Dictionary<int, Dictionary<string, object>> GetQueryResultSet(string sqlQuery)
        {
            OracleDataReader dataReader;
            Dictionary<Int32, Dictionary<String, Object>> data = new Dictionary<Int32, Dictionary<String, Object>>();
            Dictionary<String, Object> row = new Dictionary<String, Object>();
            try
            {
                this.ConnectDB();

                sqlComm = new OracleCommand();
                sqlComm.Connection = sqlConn;
                sqlComm.CommandText = sqlQuery;
                dataReader = sqlComm.ExecuteReader();
                row = new Dictionary<String, Object>();
                int indexRow = 0;
                while (dataReader.Read())
                {
                    indexRow++;
                    for (int indexColumn = 0; indexColumn < dataReader.FieldCount; indexColumn++)
                    {
                        row.Add(dataReader.GetName(indexColumn), dataReader.GetOracleValue(indexColumn));
                    }
                    data.Add(indexRow, row);
                }

            }
            catch (Exception)
            {
            }
            finally
            {
                this.CloseDB();
            }

            return data;
        }

        public bool CloseDB()
        {
            try
            {
                sqlConn.Close();

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}