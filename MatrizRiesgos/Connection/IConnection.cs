using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MatrizRiesgos.Util
{
    public interface IConnection
    {
        Boolean ConnectDB();
        Dictionary<Int32, Dictionary<String, Object>> GetQueryResultSet(string sqlQuery);
        Boolean CloseDB();
    }
}
