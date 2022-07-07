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
        private OracleDataReader dataReader;
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
                
                string connectionstring = WebConfigurationManager.AppSettings["DBOraDataSource"];
                return connectionstring;
            }
            catch (Exception)
            {
                return "";
            }
        }

        public Dictionary<int, Dictionary<string, object>> GetQueryResultSet(string sqlQuery)
        {
            Dictionary<Int32, Dictionary<String, Object>> data = new Dictionary<Int32, Dictionary<String, Object>>();
            Dictionary<String, Object> row = new Dictionary<String, Object>();
            try
            {
                this.ConnectDB();

                sqlComm = new OracleCommand();
                sqlComm.Connection = sqlConn;
                sqlComm.CommandText = sqlQuery;
                dataReader = sqlComm.ExecuteReader();
                int indexRow = 0;
                while (dataReader.Read())
                {
                    row = new Dictionary<String, Object>();
                    for (int indexColumn = 0; indexColumn < dataReader.FieldCount; indexColumn++)
                    {
                        row.Add(dataReader.GetName(indexColumn), dataReader.GetOracleValue(indexColumn));
                    }
                    data.Add(indexRow, row);
                    indexRow++;
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

        public List<Util.EllRow> GetQueryResultSet(string sqlQuery, List<string> columnsAttribute)
        {
            List<Util.EllRow> rows = new List<Util.EllRow>();
            try
            {
                this.ConnectDB();

                sqlComm = new OracleCommand();
                sqlComm.Connection = sqlConn;
                sqlComm.CommandText = sqlQuery;
                dataReader = sqlComm.ExecuteReader();
                
                while (dataReader.Read())
                {
                    //row = new Dictionary<String, Object>();
                    Util.EllRow rowEll = new Util.EllRow();
                    rowEll.atts = new List<Attribute>();
                    //for (int indexColumn = 0; indexColumn < columnsAttribute.Count; indexColumn++)
                    //{
                        rowEll.atts.Add(CreateUtilAttribute(columnsAttribute[0], dataReader[0].ToString()));
                        rowEll.atts.Add(CreateUtilAttribute(columnsAttribute[1], dataReader[1].ToString()));
                        rowEll.atts.Add(CreateUtilAttribute(columnsAttribute[2], dataReader[2].ToString()));
                    //}
                    rows.Add(rowEll);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                this.CloseDB();
            }

            return rows;
        }

        public Util.Attribute CreateUtilAttribute(string name, string value)
        {
            Util.Attribute att = new Util.Attribute();
            att.name = name;
            att.value = value;

            return att;
        }

        public bool CloseDB()
        {
            try
            {
                sqlComm.Dispose();
                try { dataReader.Close(); } catch (Exception) { }
                try { dataReader.Dispose(); } catch (Exception) { }

                try { sqlConn.Close(); } catch (Exception) { }
                try { sqlConn.Dispose(); } catch (Exception) { }                

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}