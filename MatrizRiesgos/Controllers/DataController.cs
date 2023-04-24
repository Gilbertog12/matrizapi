using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;
using System.Web.Configuration;
using MatrizRiesgos.GenericScriptService;
using EllipseWebServicesClient;
using MatrizRiesgos.Util;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Web;
using NLog;
using Newtonsoft.Json;
using System.Globalization;
using NLog.Targets;
using NLog.Config;
using NLog.Layouts;
using System.Reflection;
using System.Net.Http.Headers;
using System.Collections;
/* Historia
 * * 2022-07-24 v2.23a Llamar IMO_BUSCAR_NOTIFICACIONES en un loop
* 2022-07-24 v2.23 Se agregan metodo para notificacion via PUSH.
* 2022-07-08 v2.22 Se agrega metodo para descargar un log dado el nombre del archivo.
* 2022-07-08 v2.21 Se agrega metodo para listar los logs dado una fecha.
* 2022-07-07 v2.20 Se agrega log con el valor del RunAs si es pasado. Se agrega condicion para evitar el [NaN] al obtener el serverTime.
* 2022-06-12 v2.19 Se agrega condicion para establecer la autenticacion contra el Directorio Activo.
* 2022-04-27 v2.18 Se uiliza acceso directo a la BD de replica para poder desplegar de forma rapida las listas desplegables.
*                  Se crea clave DIRECTLIST en el WebConfig para determinar que servicios van a ser directos BD o indirectos coemdr.groovy
* 2022-04-27 v2.17 Evitar acceso Oracle para obtener posicion, ahora viene en el header desde Cursor
*                  En el monitoreo de BD encadenamos los try-catch para no continuar si alguno falla
* 2022-04-27 v2.16 Se adiciona parametro usuario para enviarse por el atributo RunAs y asi como tambien funcionalidad para obtener la posicion por SQL.
* 2022-04-12 v2.15 Se agregan los al metodo monitor.
* 2022-04-05 v2.14 Se adiciona en el web.config parametro "bufferSize" para la inmediata escrituroa del log. Se toman solo los 4 primeros caracteres del distrito para mostrar en el log.
* 2022-04-05 v2.13 Estandarizacion de los mensajes de log .
* 2022-04-05 v2.12 Se adiciona informacion en el log de datos del request y response de los llamados al API a traves del metodo sendGeneric.
* 2022-04-03 v2.11 Se adiciona informacion en el log de datos del request y response de los llamados al API a traves del metodo sendGenericSimple.
* 2022-03-30 v2.10 Se corrige recepcion de parametros en null.
* 2022-03-22 v2.09 Se agrega metodo para obtener el password sin econding. [Clase MyAuthorizationServerProvider.cs]
* 2021-12-28 v2.08 Eliminar atts[1] del log, quitar padRight del log
* 2021-12-27 v2.07 Merge 2.05 y 2.06 para subir a GIT
* 2021-12-27 v2.06 Optimización de memoria y cpu
* 2021-12-24 v2.05 Modificacion de genericSimple en el tipo de parametro de entrada
* 2021-12-24 v2.04 Definir mensajes para RETRY - ver Rintentar(ex.Message)
*                  E3 = Error no reintentable
*                  EX = Error reintentable
*                  OR = Reintento exitoso
*                  ER = Reintento fallido
*                  Futuro: reintentar errores Groovy
*                          retornar flag "Fatal":true 
*                          ... requiere modificar MatrizRiesgos.Common.cs (httpResponse<R>)
*                          Después de re-intentar errores retornar código "Fatal" en vez de "Success"
* 2021-12-23 v2.03 Intento unificación de este componente entre Matriz de Riesgo y Matriz API
*                  Ampliar a 600 caracteres para alojar completos los mensajes RITUS mas largos
*                  Ver un "OJO" en el cambio de TLS1.2 que está en MatrizAPI y no estaba en MatrisRSK
* 2021-12-03 v2.02 Eliminar pad del distrito/posición, alargar allAtributes para que quepa Read_Consecuencia
* 2021-12-02 v2.01 Truncar mensaje SendGeneric en logs, modifica el DateTime.Now.ToString(formatDate) + ";" + por  spanMS + ";0;" +:
* 2021-12-02 v2.0- Mejoras en logs:
*            Agregar version en /api/values, quitar ruta Ellipse
*            Medir tiempo de /api/values/authenticate - GetForAuthenticate
*                            /api/values/districts - GetForDistricts
*                            /api/values/positions - GetForPositions
*                            /api/values/generic - mover info después de sendGeneric
*                            /api/values/genericSimple - simplificar info's
* 2021-12-01 Upgrade a TLS 1.2
* 2021-11-28 Si falla el generic, intentar una (1) vez genericRetry
* 2021-11-27 Reordenar INFO para facilitar análisis del log
*            Generar errores aleatorios (50%) para probar "Retry Angular" temporal - ojo
*/

namespace MatrizRiesgos.Controllers
{
    public class DataController : ApiController
    {
        readonly string versionAPI = "v2.23a";
        //private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        Logger log = NLog.LogManager.GetCurrentClassLogger();
        private static readonly string formatDate = "yyyy-MM-dd HH:mm:ss";
        private static readonly int MAX_LONG_RESPONSE = 600;
        private string previousTimeServer = "0";
        //formatDate

        [HttpGet]
        [Route("api/values")]
        public IEnumerable<string> Get()
        {
            return new string[] { WebConfigurationManager.AppSettings["EllService"], "App Matriz API Versión " + versionAPI + " ... hora del servidor : " + DateTime.Now.ToString() };
        }

        [HttpPost]
        [Route("api/cdd/uploadFile")]
        public JObject uploadFile(JObject inputParam)
        {
            string initialConfig = WebConfigurationManager.AppSettings["CDDIntegration"];
            MatrizRiesgos.Util.CDDIntegration cdd = new MatrizRiesgos.Util.CDDIntegration(initialConfig);
            cdd.Login();
            cdd.upload();

            JObject json = JObject.FromObject(new
            {
                error = "Error inesperado: "
            });

            return json;
        }

        [HttpGet]
        [Route("api/log/list")]
        public List<Filelog> getLogFileName([FromUri] string logDateFrom, [FromUri] string logDateTo)
        {
            DateTime filterLogDateFrom = DateTime.ParseExact(logDateFrom, "yyyyMMdd", null);
            DateTime filterLogDateTo = DateTime.ParseExact(logDateTo, "yyyyMMdd", null);
            return GetFileLogs(filterLogDateFrom, filterLogDateTo);
        }

        [HttpGet]
        [Route("api/log/download")]
        public HttpResponseMessage GetFile([FromUri]  string fileName)
        {
            if (String.IsNullOrEmpty(fileName))
                return Request.CreateResponse(HttpStatusCode.BadRequest);

            string localFilePath = GetFileFromName(fileName);

            HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StreamContent(new FileStream(localFilePath, FileMode.Open, FileAccess.Read));
            response.Content.Headers.ContentDisposition = new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment");
            response.Content.Headers.ContentDisposition.FileName = fileName;
            response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/txt");

            return response;
        }

        [Authorize]
        [HttpGet]
        [Route("api/values/authenticate")]
        public Util.HttpResponse<Util.BodyParams> GetForAuthenticate()
        {
            var res = new Util.BodyParams();
            var identity = (ClaimsIdentity)User.Identity;
            IEnumerable<Claim> claims = identity.Claims.ToList();
            res.username = claims.Where(f => f.Type == "username").FirstOrDefault().Value;
            res.pwd = claims.Where(f => f.Type == "pwd").FirstOrDefault().Value;
            res.district = claims.Where(f => f.Type == "district").FirstOrDefault().Value;
            res.position = claims.Where(f => f.Type == "position").FirstOrDefault().Value;
            return new Util.HttpResponse<Util.BodyParams>() { data = res, message = "Datos de : " + claims.Where(f => f.Type == "username").FirstOrDefault().Value, redirect = false, success = true };
        }

        [Authorize]
        [HttpPost]
        [Route("api/values/generic")]
        public Util.HttpResponse<List<Util.EllRow>> generic([FromBody] Util.BodyParams value)
        {
            DateTime intialDate = DateTime.Now;
            Credentials credentials = new Credentials();
            var identity = (ClaimsIdentity)User.Identity;
            string allAttributes = "";

            IEnumerable<Claim> claims = identity.Claims.ToList();
            GenericScriptService.OperationContext opSheet = new GenericScriptService.OperationContext();
            Util.HttpResponse<List<Util.EllRow>> result = new Util.HttpResponse<List<Util.EllRow>>();
            List<Util.EllRow> data = new List<Util.EllRow>();
            List<Util.Attribute> dataitem = new List<Util.Attribute>();
            GenericScriptService.GenericScriptService proxySheet = new GenericScriptService.GenericScriptService();

            credentials.username = claims.Where(f => f.Type == "username").FirstOrDefault().Value;
            credentials.password = claims.Where(f => f.Type == "pwd").FirstOrDefault().Value;
            opSheet.district = claims.Where(f => f.Type == "district").FirstOrDefault().Value;
            opSheet.position = claims.Where(f => f.Type == "position").FirstOrDefault().Value;
            opSheet.maxInstances = 100;
            opSheet.returnWarnings = true;
            credentials.district = opSheet.district;
            credentials.position = opSheet.position;
            credentials.attributeType = "JSONELL";

            EllipseWebServicesClient.ClientConversation.username = credentials.username;
            EllipseWebServicesClient.ClientConversation.password = credentials.password;

            GenericScriptService.GenericScriptDTO genericScriptDTO = new GenericScriptService.GenericScriptDTO();
            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam = new GenericScriptService.GenericScriptSearchParam();
            try
            {
                proxySheet.Url = WebConfigurationManager.AppSettings["EllService"] + "GenericScriptService";

                //Este parametro se utiliza saber donde esta el script con el SQL a ejecutar
                List<GenericScriptService.Attribute> atts = new List<GenericScriptService.Attribute>();
                GenericScriptService.Attribute att = new GenericScriptService.Attribute();

                foreach (var item in value.atts)
                {
                    att = new GenericScriptService.Attribute();
                    att.name = item.name;
                    att.value = item.value;
                    atts.Add(att);
                }

                genericScriptDTO.scriptName = value.script_name;
                genericScriptDTO.customAttributes = atts.ToArray();
                genericScriptSearchParam.customAttributes = atts.ToArray();

                result = sendGeneric(opSheet, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);

            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                bool reintentar = Rintentar(ex.Message);
                string codigoError = "E3";
                if (reintentar) codigoError = "EX";
                Info(intialDate.ToString(formatDate) + ";generic;genericException;" + codigoError + ";0;" +
                    spanMS + ";" +
                    credentials.runasUsername + ";" +
                    credentials.district + ";" +
                    opSheet.position + ";" +
                    ex.Message + ";\n" + ex.StackTrace);
                if (reintentar)
                {
                    intialDate = DateTime.Now;
                    try
                    {
                        result = sendGeneric(opSheet, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);
                        if (allAttributes.Length > MAX_LONG_RESPONSE)
                        {
                            allAttributes = allAttributes.Substring(0, MAX_LONG_RESPONSE) + "...";
                        }
                        span = DateTime.Now - intialDate;
                        spanMS = (long)span.TotalMilliseconds;
                        Info(intialDate.ToString(formatDate) + ";generic;genericRetry;OR;" +
                            spanMS + ";0;" +
                            credentials.runasUsername + ";" +
                            credentials.district + ";" +
                            opSheet.position + ";" +
                            allAttributes + ";" + ex.Message);
                    }
                    catch (Exception ex2)
                    {
                        span = DateTime.Now - intialDate;
                        spanMS = (long)span.TotalMilliseconds;
                        Info(intialDate.ToString(formatDate) + ";generic;genericRetry;ER;" +
                            spanMS + ";0;" +
                            credentials.runasUsername + ";" +
                            credentials.district + ";" +
                            opSheet.position + ";" +
                            allAttributes + ";" + ex2.Message + "\n" + ex2.StackTrace);

                        result.message = ex2.Message;
                        result.data = new List<Util.EllRow>();
                        result.success = false;
                    }
                }
                else
                {
                    result.message = ex.Message;
                    result.data = new List<Util.EllRow>();
                    result.success = false;
                }
            }
            proxySheet.Abort();
            proxySheet.Dispose();
            return result;
        }

        [Authorize]
        [HttpPost]
        [Route("api/values/genericSimple")]
        public JObject genericSimple([FromBody] HttpRequestMessage value2)
        {
            DateTime intialDate = DateTime.Now;
            string value = GetRequestBody();
            string allAttributes = "";
            string actionPparam = "";
            string scriptNameParam = "";
            JObject json = null;

            Credentials credentials = new Credentials();
            var identity = (ClaimsIdentity)User.Identity;

            IEnumerable<Claim> claims = identity.Claims.ToList();
            GenericScriptService.OperationContext opSheet = new GenericScriptService.OperationContext();
            Util.HttpResponse<List<Util.EllRow>> result = new Util.HttpResponse<List<Util.EllRow>>();
            List<Util.EllRow> data = new List<Util.EllRow>();
            List<Util.Attribute> dataitem = new List<Util.Attribute>();
            GenericScriptService.GenericScriptService proxySheet = new GenericScriptService.GenericScriptService();

            credentials.username = claims.Where(f => f.Type == "username").FirstOrDefault().Value;
            credentials.password = claims.Where(f => f.Type == "pwd").FirstOrDefault().Value;
            opSheet.district = claims.Where(f => f.Type == "district").FirstOrDefault().Value;
            opSheet.position = claims.Where(f => f.Type == "position").FirstOrDefault().Value;
            opSheet.maxInstances = 100;
            opSheet.returnWarnings = true;
            credentials.district = opSheet.district;
            credentials.position = opSheet.position;
            credentials.attributeType = "JSON";
            EllipseWebServicesClient.ClientConversation.username = credentials.username;
            EllipseWebServicesClient.ClientConversation.password = credentials.password;

            GenericScriptService.GenericScriptDTO genericScriptDTO = new GenericScriptService.GenericScriptDTO();
            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam = new GenericScriptService.GenericScriptSearchParam();

            try
            {
                proxySheet.Url = WebConfigurationManager.AppSettings["EllService"] + "GenericScriptService";
                JObject inputJson = JObject.Parse(value);
                List<GenericScriptService.Attribute> atts = ConvertParamsToEllipse(inputJson);
                allAttributes = value;

                genericScriptDTO.customAttributes = atts.ToArray();
                genericScriptSearchParam.customAttributes = atts.ToArray();

                actionPparam = GetParamValue(inputJson, "action");
                scriptNameParam = GetParamValue(inputJson, "scriptName");

                result = sendGeneric(opSheet, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);

                if (result.data[0].atts[0].name.ToLower().Contains("json"))
                {
                    json = JObject.Parse(result.data[0].atts[0].value);
                }
            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";" + scriptNameParam + ";" + actionPparam + ";E6;" +
                    spanMS + ";0;" +
                    credentials.runasUsername + ";" +
                    credentials.district + ";" +
                    opSheet.position + ";" +
                    allAttributes + ";" + ex.Message + "\n" + ex.StackTrace);

                json = JObject.FromObject(new
                {
                    error = "Error inesperado: " + ex.Message
                });
            }

            proxySheet.Abort();
            proxySheet.Dispose();
            return json;//new HttpResponseMessage();
        }

        private void BuildRequestInfo(Util.HttpResponse<List<Util.EllRow>> result, DateTime intialDate, Credentials credentials, String allAttributes)
        {
            string actionPparam = credentials.actionName;
            string scriptNameParam = credentials.scriptName;
            string time = "";

            if (allAttributes.Length > MAX_LONG_RESPONSE)
            {
                allAttributes = allAttributes.Substring(0, MAX_LONG_RESPONSE);
            }

            try
            {
                time = GetParamValue(result.data, "time");
            }
            catch (Exception)
            {
                time = "0";
            }

            TimeSpan span = DateTime.Now - intialDate;
            long spanMS = (long)span.TotalMilliseconds;
            Info(intialDate.ToString(formatDate) + ";" + scriptNameParam + ";" + actionPparam + ";OK;" +
                spanMS + ";" + GetTimeValue(time) + ";" +
                credentials.runasUsername + ";" +
                credentials.district + ";" +
                credentials.runasPosition + ";" +
                allAttributes);
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("api/values/monitor")]
        public JObject monitor([FromBody] JObject data)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            Util.HttpResponse<List<Util.EllRow>> response = new HttpResponse<List<EllRow>>();
            DateTime intialDate = DateTime.Now;
            string mensaje = "";
            string serverTime = "";
            string timeParam = "";
            string sql = "";
            string pbi = "0";
            string responseTime = "";
            long spanMS = 0;
            TimeSpan spanlog;
            JObject jobjectResult = null;

            Credentials credentials = new Credentials();
            credentials.username = WebConfigurationManager.AppSettings["EllipseUsername"];
            credentials.password = WebConfigurationManager.AppSettings["EllipsePassword"];
            credentials.district = WebConfigurationManager.AppSettings["EllipseDistrict"];
            credentials.position = WebConfigurationManager.AppSettings["EllipsePosition"];
            credentials.attributeType = "XML";

            OperationContext oc = new OperationContext();
            oc.district = credentials.district;
            oc.position = credentials.position;
            mensaje = mensaje + "TOKEN-";
            GenericScriptService.GenericScriptService proxySheet = new GenericScriptService.GenericScriptService();
            proxySheet.Url = WebConfigurationManager.AppSettings["EllService"] + "GenericScriptService";

            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam = new GenericScriptService.GenericScriptSearchParam();
            genericScriptSearchParam.customAttributes = new GenericScriptService.Attribute[]
            {
                CreateAttribute("scriptName","coeimo"),
                CreateAttribute("action","IMO_ACTUALIZAR_MSF010")
            };
            mensaje = mensaje + "IMO_ACTUALIZAR-";
            GenericScriptService.GenericScriptDTO genericScriptDTO = new GenericScriptService.GenericScriptDTO();
            genericScriptDTO.customAttributes = genericScriptSearchParam.customAttributes;
            genericScriptDTO.scriptName = "coeimo";
            string falla = "Falla llamado IMO_ACTUALIZAR_MSF010";
            try
            {
                //string allAttributes = GetAllRequestParam(genericScriptDTO.customAttributes);
                response = sendGeneric(oc, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);
                //Recibir el response: IF code == 200 
                //Obtener el “serverTime”
                mensaje = mensaje + "SERVERTIME-";
                if (response.data[0].atts[0].name.ToLower().Contains("json"))
                {
                    JObject json = JObject.Parse(response.data[0].atts[0].value);
                    serverTime = GetParamValue(json, "serverTime");
                    falla = "";
                }
                else
                {
                    foreach (Util.EllRow rows in response.data)
                    {
                        foreach (Util.Attribute att in rows.atts)
                        {
                            if (att.name.Equals("serverTime"))
                            {
                                serverTime = att.value;
                                falla = "";
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                mensaje = mensaje + ex.Message;
            }


            //Conectarse a Oracle con la tupla DBname, user, pass, ip, puerto
            //Ejecutar el comando SQL del punto 3
            IConnection conn = new ConnectionOracleImpl();
            DateTime replDateTime = new DateTime();
            DateTime serverDateTime = new DateTime();
            if (falla == "")
            {
                try
                {
                    mensaje = mensaje + "ORACLETIME-";
                    sql = "select table_desc, last_mod_date, last_mod_time from ELLIPSE.msf010 where table_type = 'HOST' and table_code = 'REPL'";
                    Dictionary<int, Dictionary<string, object>> dataQuery = conn.GetQueryResultSet(sql);
                    if (dataQuery.Count() == 0)
                    {
                        falla = "MSF010:REPL not found";
                        jobjectResult = JObject.FromObject(new
                        {
                            code = "501",
                            message = "NO EXISTEN REGISTROS EN LA TABLA MSF010 TABLE_CODE[HOST] TABLE_TYPE[REPL]"
                        });
                    }
                    else
                    {

                        string lastModDate = dataQuery[0]["LAST_MOD_DATE"].ToString();
                        string lastModtime = dataQuery[0]["LAST_MOD_TIME"].ToString();

                        replDateTime = DateTime.ParseExact(lastModDate + lastModtime, "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
                        serverDateTime = DateTime.ParseExact(serverTime.Replace(" ", ""), "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
                    }
                }
                catch (Exception ex)
                {
                    falla = "Falla cnx Oracle";
                    mensaje = mensaje + ex.Message;
                    jobjectResult = JObject.FromObject(new
                    {
                        code = "501",
                        message = "ERROR EN EL FORMATO DE LAS FECHAS [yyyyMMddHHmmss]"
                    });
                }
            }
            TimeSpan span = serverDateTime - replDateTime;
            //Llamar al servicio IMO_STATUS_MSF010 usando el request del punto 6
            if (falla == "")
            {
                try
                {
                    falla = "Falla llamado a IMO_ALARMA_MSF010";
                    responseTime = Math.Abs(span.TotalSeconds).ToString();
                    mensaje = mensaje + "IMO_ALARMA-";
                    genericScriptSearchParam.customAttributes = new GenericScriptService.Attribute[]
                    {
                        CreateAttribute("scriptName","coeimo"),
                        CreateAttribute("action","IMO_ALARMA_MSF010"),
                        CreateAttribute("responseTime",Math.Abs(span.TotalSeconds).ToString())
                    };
                    genericScriptDTO.customAttributes = genericScriptSearchParam.customAttributes;
                    response = sendGeneric(oc, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);

                    try
                    {
                        if (response.data[0].atts[0].name.ToLower().Contains("json"))
                        {
                            JObject json = JObject.Parse(response.data[0].atts[0].value);
                            timeParam = GetParamValue(json, "time");
                            falla = "";
                        }
                    }
                    catch (Exception)
                    {
                        timeParam = "0";
                    }
                }
                catch (Exception e)
                {
                    mensaje = mensaje + e.Message;
                    jobjectResult = JObject.FromObject(new
                    {
                        code = "501",
                        message = "ERROR EN LA EJECUCION DEL PROCESO IMO_ALARMA_MSF010 " + e.Message
                    });
                }
            }
            //POWER BI
            if (falla == "")
            {
                try
                {
                    falla = "Falla grabar en PowerBI";
                    pbi = data.GetValue("sendToPowerBI").ToString();
                    if (pbi.Equals("1"))
                    {
                        JObject json = JObject.FromObject(new
                        {
                            date = DateTime.Now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
                            timeAPI = replDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                            timeE9 = serverDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                            span = Int32.Parse(responseTime)
                        });
                        mensaje = mensaje + "PBI-";
                        sendStatisticToPowerBI(json);
                        falla = "";
                    }
                }
                catch (Exception ex)
                {
                    mensaje = mensaje + ex.Message;
                    jobjectResult = JObject.FromObject(new
                    {
                        code = "501",
                        menssage = "ERROR " + ex.Message
                    });
                }
            }
            mensaje = mensaje + "FALLA=" + falla;
            spanlog = DateTime.Now - intialDate;
            spanMS = (long)spanlog.TotalMilliseconds;

            Info(intialDate.ToString(formatDate) + ";MatrizApi;monitor;OK;" +
                spanMS + ";0;" +
                credentials.runasUsername + ";" +
                credentials.district + ";" +
                credentials.runasPosition + ";" +
                mensaje + ";\n");

            if (jobjectResult == null)
            {
                jobjectResult = JObject.FromObject(new
                {
                    code = "200",
                    menssage = "MONITOREO EFECTUADO CORRECTAMENTE"
                });
            }

            return jobjectResult;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("api/values/notification")]
        public JObject notification([FromBody] JObject data)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            Util.HttpResponse<List<Util.EllRow>> response = new HttpResponse<List<EllRow>>();
            DateTime intialDate = DateTime.Now;

            JObject jobjectResult = null;
            string messageResponse = "";
            string messageCode = "";
            string apps  = WebConfigurationManager.AppSettings["CursorPUSHApp"];
            Credentials credentials = new Credentials();
            credentials.username = WebConfigurationManager.AppSettings["EllipseUsername"];
            credentials.password = WebConfigurationManager.AppSettings["EllipsePassword"];
            credentials.district = WebConfigurationManager.AppSettings["EllipseDistrict"];
            credentials.position = WebConfigurationManager.AppSettings["EllipsePosition"];
            credentials.attributeType = "JSON";

            OperationContext oc = new OperationContext();
            oc.district = credentials.district;
            oc.position = credentials.position;
            foreach (string app in apps.Split(','))
            {

                int maximo = 100;
                while (maximo > 0)
                {
                    maximo = maximo - 1;
                    GenericScriptService.GenericScriptService proxySheet = new GenericScriptService.GenericScriptService();
                    proxySheet.Url = WebConfigurationManager.AppSettings["EllService"] + "GenericScriptService";
                    //IMO_BUSCAR_NOTIFICACIONES
                    GenericScriptService.GenericScriptSearchParam genericScriptSearchParam = new GenericScriptService.GenericScriptSearchParam();
                    genericScriptSearchParam.customAttributes = new GenericScriptService.Attribute[]
                    {
                    CreateAttribute("scriptName","coeimo"),
                    CreateAttribute("action","IMO_BUSCAR_NOTIFICACIONES"),
                    CreateAttribute("programa",app)
                    };

                    GenericScriptService.GenericScriptDTO genericScriptDTO = new GenericScriptService.GenericScriptDTO();
                    genericScriptDTO.customAttributes = genericScriptSearchParam.customAttributes;
                    genericScriptDTO.scriptName = "coeimo";

                    JObject jsonMessageNotifcation = null;

                    try
                    {
                        response = sendGeneric(oc, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);

                        if (response.data[0].atts[0].name.ToLower().Contains("json"))
                        {
                            jsonMessageNotifcation = JObject.Parse(response.data[0].atts[0].value);
                            jsonMessageNotifcation["version"].Parent.Remove();
                            jsonMessageNotifcation["time"].Parent.Remove();
                        }
                    }
                    catch (Exception)
                    {
                        maximo = 0;
                        //deberiamos dejar un log del error
                    }

                    if (!jsonMessageNotifcation.GetValue("programa").ToString().Equals(""))
                    {
                        //Enviar notificaciones a Cursor
                        APIRequest notificationAPI = new APIRequest();
                        notificationAPI.ContentType = "application/json";
                        notificationAPI.UrlAPI = WebConfigurationManager.AppSettings["CursorPUSHUrl"];
                        notificationAPI.Method = "POST";
                        notificationAPI.AddHeaderParam("X-Secret", WebConfigurationManager.AppSettings["CursorPUSHKey"]);
                        notificationAPI.BodyParams = jsonMessageNotifcation.ToString();
                        JObject jsonResponse = notificationAPI.SendRequest();

                        if (!notificationAPI.ErrorFound)
                        {

                            //IMO_ACTUALIZAR_NOTIFICACIONES
                            List<MatrizRiesgos.GenericScriptService.Attribute> listAttribute = new List<GenericScriptService.Attribute>();
                            listAttribute.Add(CreateAttribute("scriptName", "coeimo"));
                            listAttribute.Add(CreateAttribute("action", "IMO_ACTUALIZAR_NOTIFICACIONES"));
                            listAttribute.Add(CreateAttribute("success", jsonResponse.GetValue("success").ToString()));
                            IEnumerator enumerator = jsonMessageNotifcation.Properties().GetEnumerator();
                            while (enumerator.MoveNext())
                            {
                                JProperty item = (JProperty)enumerator.Current;
                                listAttribute.Add(CreateAttribute(item.Name, item.Value.ToString()));
                            }

                            genericScriptSearchParam.customAttributes = listAttribute.ToArray();
                            genericScriptDTO.customAttributes = genericScriptSearchParam.customAttributes;
                            try
                            {
                                response = sendGeneric(oc, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);

                                if (response.data[0].atts[0].name.ToLower().Contains("json"))
                                {
                                    jsonMessageNotifcation = JObject.Parse(response.data[0].atts[0].value);
                                }
                                jobjectResult = jsonMessageNotifcation;
                            }
                            catch (Exception ex)
                            {
                                messageCode = "400";
                                messageResponse = ex.Message;
                                maximo = 0;
                            }

                        }
                        else
                        {
                            messageCode = "400";
                            messageResponse = notificationAPI.ErrorMessage;
                            maximo = 0;
                        }
                    }
                    else
                    {
                        messageCode = "200";
                        messageResponse = "ITERACION REALIZADA CORRECTAMENNTE";
                    }
                }

                if (jobjectResult == null)
                {
                    jobjectResult = JObject.FromObject(new
                    {
                        code = messageCode,
                        menssage = messageResponse
                    });
                }

            }
                return jobjectResult;


        }

        [AllowAnonymous]
        [HttpPost]
        [Route("api/values/districts")]
        public Util.HttpResponse<List<Util.EllRow>> GetForDistricts([FromBody] JObject data)
        {
            Credentials credentials = new Credentials();
            DateTime intialDate = DateTime.Now;

            credentials.username = data.GetValue("username").ToString();
            credentials.password = data.GetValue("pwd").ToString();

            if (string.IsNullOrEmpty(WebConfigurationManager.AppSettings["EllipseDistrict"]))
            {
                return GetDefaultDistrict(credentials);
            }
            else
            {
                string userToFind = credentials.username.Split('@')[0];
                credentials.username = WebConfigurationManager.AppSettings["EllipseUsername"];
                credentials.password = WebConfigurationManager.AppSettings["EllipsePassword"];
                credentials.district = WebConfigurationManager.AppSettings["EllipseDistrict"];
                credentials.position = WebConfigurationManager.AppSettings["EllipsePosition"];
                credentials.attributeType = "ELLJSON";
                return GetDefaultDistrictByGroovy(userToFind, credentials);
            }

        }


        [AllowAnonymous]
        [HttpGet]
        [Route("api/values/forall")]
        public Util.HttpResponse<string> GetF()
        {
            return new Util.HttpResponse<string>() { data = "", message = "App Matriz de riesgos Versión " + versionAPI + " ... hora del servidor : " + DateTime.Now.ToString(), redirect = false, success = true };
        }

        [AllowAnonymous]
        [HttpGet]
        [Route("api/values/attachments")]
        public HttpResponseMessage GetAttachments(string scriptName, string primaryKey, string blobUUID)
        {
            String fileInB64 = "";
            String fileName = "";
            String fileType = "";
            Credentials credentials = new Credentials();

            credentials.username = WebConfigurationManager.AppSettings["EllipseUsername"];
            credentials.password = WebConfigurationManager.AppSettings["EllipsePassword"];
            credentials.district = WebConfigurationManager.AppSettings["EllipseDistrict"];
            credentials.position = WebConfigurationManager.AppSettings["EllipsePosition"];

            Util.HttpResponse<List<Util.EllRow>> resp = GetAttachmentByGroovy(primaryKey, blobUUID, scriptName, credentials);
            List<Util.EllRow> dataResp = resp.data;

            foreach (Util.Attribute atts in dataResp[0].atts)
            {
                if (atts.name.Equals("fileName"))
                {
                    fileName = atts.value;
                }
                if (atts.name.Equals("fileType"))
                {
                    fileType = atts.value;
                }
                if (atts.name.Equals("fileData"))
                {
                    fileInB64 = atts.value;
                }
            }

            HttpResponseMessage httpResponseMessage = Request.CreateResponse(HttpStatusCode.OK);

            if (fileInB64.Length > 0)
            {
                byte[] dataBytes = Convert.FromBase64String(fileInB64);
                MemoryStream dataStream = new MemoryStream(dataBytes);

                httpResponseMessage.Content = new StreamContent(dataStream);
                httpResponseMessage.Content.Headers.ContentDisposition = new System.Net.Http.Headers.ContentDispositionHeaderValue("attachment");
                httpResponseMessage.Content.Headers.ContentDisposition.FileName = fileName.Trim() + "." + fileType.Trim();
                httpResponseMessage.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
            }
            return httpResponseMessage;
        }


        private Util.HttpResponse<List<Util.EllRow>> sendGeneric(GenericScriptService.OperationContext opSheet,
            GenericScriptService.GenericScriptService proxySheet,
            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam,
            GenericScriptService.GenericScriptDTO genericScriptDTO,
            Credentials credentials)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            List<GenericScriptService.Attribute> paramList = genericScriptSearchParam.customAttributes.ToList();
            List<Util.EllRow> data = new List<EllRow>();
            //Intervencion de Rene ... renombrar parametro user, obtener posicion, estandarizar null, runAS con user+posi
            string userRunedAs = GetRequestHeader("usuario");
            string posiRunedAs = GetRequestHeader("posicion");
            string moduleRunedAs = GetRequestHeader("modulo");
            proxySheet.RequestEncoding = System.Text.Encoding.UTF8;

            DateTime intialDate = DateTime.Now;
            if (userRunedAs == "") userRunedAs = null;
            if (userRunedAs != null)
            {
                userRunedAs = userRunedAs.Trim();
                paramList.Add(CreateAttribute("usuario", userRunedAs));
            }

            if (posiRunedAs == "") posiRunedAs = null;
            if (posiRunedAs != null)
            {
                posiRunedAs = posiRunedAs.Trim();
                paramList.Add(CreateAttribute("posicion", posiRunedAs));
            }

            if (moduleRunedAs == "") moduleRunedAs = null;
            if (moduleRunedAs != null)
            {
                moduleRunedAs = moduleRunedAs.Trim();
                paramList.Add(CreateAttribute("modulo", moduleRunedAs));
            }

            RunAs runAs = new RunAs();
            if (userRunedAs != null && posiRunedAs != null)
            {
                runAs.district = opSheet.district;
                runAs.user = userRunedAs.Split('@')[0];
                //runAs.position = GetDefaultPositionBySQL(runAs.user);
                runAs.position = posiRunedAs;
                opSheet.runAs = runAs;

                credentials.runasUsername = userRunedAs.Split('@')[0];
                credentials.runasPosition = posiRunedAs;
                
            }

            genericScriptSearchParam.customAttributes = paramList.ToArray();
            string scriptNameParam = GetParamValue(genericScriptSearchParam, "scriptName");
            string scriptActionParam = GetParamValue(genericScriptSearchParam, "action");

            credentials.actionName = scriptActionParam;
            credentials.scriptName = scriptNameParam;
            EllipseWebServicesClient.ClientConversation.username = credentials.username;
            EllipseWebServicesClient.ClientConversation.password = credentials.password;

            Util.HttpResponse<List<Util.EllRow>> result = new Util.HttpResponse<List<Util.EllRow>>();
            //bool redirect = false;

            Dictionary<String, String> directMapAction = GetDirectAction();
            if (directMapAction.ContainsKey(scriptActionParam))
            {
                string tableType = directMapAction[scriptActionParam];
                data = GetDirectGenericData(scriptActionParam, tableType);
            }
            else
            {
                data = GetEllipseGenericData(proxySheet, opSheet, genericScriptSearchParam, genericScriptDTO, credentials, intialDate);
            }

            result.redirect = null;
            result.message = "Generic se ejecuto Correctamente";
            result.data = data;
            result.success = true;

            credentials.scriptName = scriptNameParam;
            credentials.actionName = scriptActionParam;

            if (credentials.attributeType.Equals("JSON"))
                BuildRequestInfo(result, intialDate, credentials, GetRequestBody());
            else
                BuildRequestInfo(result, intialDate, credentials, GetAllRequestParam(genericScriptDTO.customAttributes.ToArray()));
            return result;
        }

        private List<Util.EllRow> GetDirectGenericData(string scriptActionParam, string tableTypeWithPrefix)
        {
            List<Util.EllRow> data = new List<EllRow>();

            IConnection conn = new ConnectionOracleImpl();
            string tableType = GetTableTypeWithoutPrefix(scriptActionParam, tableTypeWithPrefix);
            string prefix = GetPrefix(scriptActionParam, tableTypeWithPrefix);

            string sql = "select trim(TABLE_CODE), trim(TABLE_DESC), trim(TABLE_CODE) || ' - ' || trim(TABLE_DESC) from ELLIPSE.msf010 where table_type = '" + tableType + "'";
            List<string> attributeList = new List<string>();
            attributeList.Add(prefix + "Id");
            attributeList.Add(prefix + "Descripcion");
            attributeList.Add(prefix + "DescripcionSola");
            data = conn.GetQueryResultSet(sql, attributeList);

            return data;
        }

        private string GetPrefix(string scriptActionParam, string tableTypeWithPrefix)
        {
            string prefix = "";
            try
            {
                prefix = scriptActionParam.Split(',')[1].ToLower();
            }
            catch (Exception)
            {
                prefix = scriptActionParam.Split('_')[0].ToLower();
            }

            return prefix;
        }

        private string GetTableTypeWithoutPrefix(string scriptActionParam, string tableTypeWithPrefix)
        {
            string tableTypeWithoutPrefix = "";
            try
            {
                tableTypeWithoutPrefix = tableTypeWithPrefix.Split(',')[0];
            }
            catch (Exception)
            {

            }

            return tableTypeWithoutPrefix;
        }

        private List<Util.EllRow> GetEllipseGenericData(GenericScriptService.GenericScriptService proxySheet,
            GenericScriptService.OperationContext opSheet,
            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam,
            GenericScriptService.GenericScriptDTO genericScriptDTO,
            Credentials credentials, DateTime intialDate)
        {
            List<Util.EllRow> data = new List<EllRow>();
            string errors = "";

            GenericScriptService.GenericScriptServiceResult[] genericScriptServiceResults = proxySheet.executeForCollection(opSheet, genericScriptSearchParam, genericScriptDTO);

            foreach (GenericScriptService.GenericScriptServiceResult genericScriptServiceResult in genericScriptServiceResults)
            {
                var row = new Util.EllRow();
                row.atts = new List<Util.Attribute>();
                data.Add(row);

                foreach (Error error in genericScriptServiceResult.errors)
                {
                    errors = errors + error.messageText + " - ";
                }

                if (genericScriptServiceResult.errors.Length == 0)
                {
                    GenericScriptService.GenericScriptDTO dto = genericScriptServiceResult.genericScriptDTO;

                    foreach (GenericScriptService.Attribute attribute in dto.customAttributes)
                    {
                        row.atts.Add(new Util.Attribute() { name = attribute.name, value = attribute.value });
                    }
                }
                else
                {
                    row.atts.Add(new Util.Attribute() { name = "type", value = "E" });
                    row.atts.Add(new Util.Attribute() { name = "description", value = genericScriptServiceResult.errors[0].messageText });
                    //if (genericScriptServiceResult.errors[0].messageText == "USUARIO NO TIENE PRIVILEGIOS A LA MATRIZ DE RIESGOS") { redirect = true; }
                }
            }

            //capturar error
            if (data.Count > 0)
            {
                if (data[0].atts.Count > 0)
                {
                    string timeParam = GetParamValue(genericScriptServiceResults, "time");

                    Info(intialDate.ToString(formatDate) + ";" + credentials.scriptName + ";" + credentials.actionName + ";OK;" +
                        "0;" + GetTimeValue(timeParam) + ";" +
                        credentials.runasUsername + ";" +
                        credentials.district + ";" +
                        credentials.runasPosition + ";" +
                        " " + data[0].atts[0].value);

                    if (data[0].atts[0].name == "type" && data[0].atts[0].value == "E")
                    {
                        throw new Exception(data[0].atts[1].value);
                    }
                    if (data[0].atts[0].name == "error")
                    {
                        throw new Exception(data[0].atts[0].value);
                    }
                }
            }

            return data;
        }

        private Dictionary<string, string> GetDirectAction()
        {
            Dictionary<string, string> directMap = new Dictionary<string, string>();

            string directList = WebConfigurationManager.AppSettings["DIRECTLIST"];
            if (!string.IsNullOrEmpty(directList))
            {
                foreach (string row in directList.Split(';'))
                {
                    string key = row.Split(':')[0];
                    string value = row.Split(':')[1];

                    directMap.Add(key, value);
                }
            }

            return directMap;
        }

        private Util.HttpResponse<List<Util.EllRow>> execute(List<GenericScriptService.Attribute> atts, Credentials credentials)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            DateTime intialDate = DateTime.Now;

            List<Util.EllRow> data = new List<Util.EllRow>();
            Util.EllRow row = new Util.EllRow();
            row.atts = new List<Util.Attribute>();

            GenericScriptService.OperationContext opSheet = new GenericScriptService.OperationContext
            {
                district = credentials.district,
                position = credentials.position,
                maxInstances = 100,
                returnWarnings = true
            };

            ClientConversation.username = credentials.username;
            ClientConversation.password = credentials.password;
            string URL = WebConfigurationManager.AppSettings["EllService"];
            GenericScriptService.GenericScriptService proxySheet = new GenericScriptService.GenericScriptService
            {
                Url = URL + "GenericScriptService"
            };
            try
            {
                GenericScriptDTO genericScriptDTO = new GenericScriptDTO
                {
                    scriptName = "coemdr",
                    customAttributes = atts.ToArray()
                };
                GenericScriptSearchParam genericScriptSearchParam = new GenericScriptSearchParam
                {
                    customAttributes = atts.ToArray()
                };

                Util.HttpResponse<List<Util.EllRow>> result = sendGeneric(opSheet, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);
                return result;
            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";execute;E8;" +
                    spanMS + ";0;" +
                    credentials.runasUsername + ";" +
                    credentials.district + ";" +
                    credentials.runasPosition + ";" +
                    ex.Message + ";\n" + ex.StackTrace);
                row.atts.Add(new Util.Attribute() { name = "ERROR", value = "ERROR AL EJECUTAR EL PROCEDIMIENTO" });
                data.Add(row);
                return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "no success", redirect = false, success = false };
            }
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("api/values/positions")]
        public Util.HttpResponse<List<Util.EllRow>> GetForPositions([FromBody] JObject data)
        {
            Credentials credentials = new Credentials();
            DateTime intialDate = DateTime.Now;

            credentials.username = data.GetValue("username").ToString();
            credentials.password = data.GetValue("pwd").ToString();

            if (string.IsNullOrEmpty(WebConfigurationManager.AppSettings["EllipsePosition"]))
            {
                return GetDefaultPosition(credentials);
            }
            else
            {
                string userToFind = credentials.username.Split('@')[0];
                credentials.username = WebConfigurationManager.AppSettings["EllipseUsername"];
                credentials.password = WebConfigurationManager.AppSettings["EllipsePassword"];
                credentials.district = WebConfigurationManager.AppSettings["EllipseDistrict"];
                credentials.position = WebConfigurationManager.AppSettings["EllipsePosition"];
                credentials.attributeType = "ELLJSON";
                return GetDefaultPositionByGroovy(userToFind, credentials);
            }
        }

        public void sendStatisticToPowerBI(JObject json)
        {
            ConnectionPowerBI powerBi = new ConnectionPowerBI();
            powerBi.Method = "POST";
            powerBi.Url = WebConfigurationManager.AppSettings["DatasetPBI"];

            powerBi.sendNotification("[" + json.ToString() + "]");
        }
        public GenericScriptService.Attribute CreateAttribute(string name, string value)
        {
            GenericScriptService.Attribute att = new GenericScriptService.Attribute();
            att.name = name;
            att.value = value;

            return att;
        }

        public Util.Attribute CreateUtilAttribute(string name, string value)
        {
            Util.Attribute att = new Util.Attribute();
            att.name = name;
            att.value = value;

            return att;
        }
        private HttpResponse<List<EllRow>> GetDefaultDistrict(Credentials credentials)
        {
            DateTime intialDate = DateTime.Now;

            List<Util.EllRow> data = new List<Util.EllRow>();
            Util.EllRow row = new Util.EllRow();
            row.atts = new List<Util.Attribute>();

            AuthenticatorService.AuthenticatorService authService = new AuthenticatorService.AuthenticatorService();
            authService.Url = WebConfigurationManager.AppSettings["EllService"] + "AuthenticatorService";
            AuthenticatorService.OperationContext oc = new AuthenticatorService.OperationContext();

            EllipseWebServicesClient.ClientConversation.username = credentials.username;
            EllipseWebServicesClient.ClientConversation.password = credentials.password;

            try
            {
                AuthenticatorService.NameValuePair[] pairs = authService.getDistricts(oc);
                foreach (AuthenticatorService.NameValuePair pair in pairs)
                {
                    row.atts.Add(new Util.Attribute() { name = pair.name, value = pair.value });
                }
                data.Add(row);
                authService.Dispose();
                return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "success", redirect = false, success = true };
            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";MatrizApi;GetDefaultDistrict;E1;" +
                    spanMS + ";0;" +
                    credentials.runasUsername + ";" +
                    "<dstr>" + ";" +
                    "<pos>" + ";" +
                    ex.Message + ";\n" + ex.StackTrace);
                row.atts.Add(new Util.Attribute() { name = "ERROR", value = "ERROR AL EJECUTAR EL PROCEDIMIENTO" });
                data.Add(row);
                return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "no success", redirect = false, success = false };
            }
        }
        public Util.HttpResponse<List<Util.EllRow>> GetDefaultDistrictByGroovy(string userToFind, Credentials credentials)
        {
            DateTime intialDate = DateTime.Now;
            List<GenericScriptService.Attribute> atts = new List<GenericScriptService.Attribute>();
            GenericScriptService.Attribute att = new GenericScriptService.Attribute();
            att.name = "user";
            att.value = userToFind.ToUpper();
            atts.Add(att);

            GenericScriptService.Attribute att2 = new GenericScriptService.Attribute();
            att2.name = "action";
            att2.value = "DISTRITOS_USUARIO";
            atts.Add(att2);

            GenericScriptService.Attribute att3 = new GenericScriptService.Attribute();
            att3.name = "scriptName";
            att3.value = "coemdr";
            atts.Add(att3);

            return execute(atts, credentials);
        }
        public Util.HttpResponse<List<Util.EllRow>> GetDefaultPosition(Credentials credentials)
        {
            DateTime intialDate = DateTime.Now;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; //ojo


            List<Util.EllRow> data = new List<Util.EllRow>();
            Util.EllRow row = new Util.EllRow();
            row.atts = new List<Util.Attribute>();

            HttpRequestMessage re = Request;
            var headers = re.Headers;

            AuthenticatorService.AuthenticatorService authService = new AuthenticatorService.AuthenticatorService();
            authService.Url = WebConfigurationManager.AppSettings["EllService"] + "AuthenticatorService";

            AuthenticatorService.OperationContext oc = new AuthenticatorService.OperationContext();

            EllipseWebServicesClient.ClientConversation.username = credentials.username;
            EllipseWebServicesClient.ClientConversation.password = credentials.password;

            try
            {
                AuthenticatorService.NameValuePair[] pairs = authService.getPositions(oc);
                foreach (AuthenticatorService.NameValuePair pair in pairs)
                {
                    row.atts.Add(new Util.Attribute() { name = pair.name, value = pair.value });
                }
                data.Add(row);
                authService.Dispose();
                return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "success", redirect = false, success = true };
            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";GetDefaultPosition;E2;" +
                    spanMS + ";0;" +
                    credentials.runasUsername + ";" +
                    "<dstr>" + ";" +
                    "<pos>" + ";" +
                    ex.Message + ";\n" + ex.StackTrace);

                row.atts.Add(new Util.Attribute() { name = "ERROR", value = "ERROR AL EJECUTAR EL PROCEDIMIENTO" + ex.Message });
                data.Add(row);
                return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "no success", redirect = false, success = false };
            }
        }
        public Util.HttpResponse<List<Util.EllRow>> GetDefaultPositionByGroovy(string username, Credentials credentials)
        {
            List<GenericScriptService.Attribute> atts = new List<GenericScriptService.Attribute>();
            GenericScriptService.Attribute att = new GenericScriptService.Attribute();
            att.name = "user";
            att.value = username.ToUpper();
            atts.Add(att);

            GenericScriptService.Attribute att2 = new GenericScriptService.Attribute();
            att2.name = "action";
            att2.value = "POSICIONES_USUARIO";
            atts.Add(att2);

            GenericScriptService.Attribute att3 = new GenericScriptService.Attribute();
            att3.name = "scriptName";
            att3.value = "coemdr";
            atts.Add(att3);

            Util.HttpResponse<List<Util.EllRow>> response = execute(atts, credentials);
            OrderData(response);
            return response;
        }

        private void OrderData(HttpResponse<List<EllRow>> response)
        {
            List<Util.EllRow> newRowList = new List<Util.EllRow>();
            EllRow newRow = new EllRow();
            newRow.atts = new List<Util.Attribute>();
            newRowList.Add(newRow);
            try
            {
                foreach (Util.EllRow row in response.data)
                {
                    newRow.atts.Add(CreateUtilAttribute(row.atts[0].value, row.atts[1].value));
                }
                response.data = newRowList;
            }
            catch (Exception)
            {

            }
        }

        public string GetDefaultPositionBySQL(string username)
        {
            string employeeId = GetEmployeeIdBySQL(username);
            string position = GetPositionBySQL(employeeId);
            return position;
        }

        public string GetEmployeeIdBySQL(string username)
        {
            IConnection conn = new ConnectionOracleImpl();
            string sql = "SELECT EMPLOYEE_ID FROM ELLIPSE.MSF020 WHERE ENTRY_TYPE = 'S'  AND ENTITY = '" + username + "'";
            Dictionary<int, Dictionary<string, object>> dataQuery = conn.GetQueryResultSet(sql);
            if (dataQuery.Count() > 0)
            {
                return dataQuery[0]["EMPLOYEE_ID"].ToString();
            }
            else
            {
                return "";
            }

        }

        public string GetPositionBySQL(string employeeId)
        {
            IConnection conn = new ConnectionOracleImpl();
            string sql = "SELECT MSF878.POSITION_ID FROM ELLIPSE.MSF878 INNER JOIN ELLIPSE.MSF870 ON MSF878.POSITION_ID = MSF870.POSITION_ID WHERE MSF878.EMPLOYEE_ID = '" + employeeId + "' AND MSF878.INV_STR_DATE >= 99999999 - TO_CHAR(SYSDATE,'YYYYMMDD') AND  ( MSF878.POS_STOP_DATE >= TO_CHAR(SYSDATE,'YYYYMMDD') OR MSF878.POS_STOP_DATE = '00000000') AND PRIMARY_POS = '0'";
            Dictionary<int, Dictionary<string, object>> dataQuery = conn.GetQueryResultSet(sql);
            if (dataQuery.Count() > 0)
            {
                return dataQuery[0]["POSITION_ID"].ToString();
            }
            else
            {
                return "";
            }

        }

        public Util.HttpResponse<List<Util.EllRow>> GetAttachmentByGroovy(string primaryKey, string blobUUID, string scriptName, Credentials credentials)
        {
            List<GenericScriptService.Attribute> atts = new List<GenericScriptService.Attribute>();
            GenericScriptService.Attribute att1 = new GenericScriptService.Attribute();
            att1.name = "primaryKey";
            att1.value = primaryKey;
            atts.Add(att1);

            GenericScriptService.Attribute att2 = new GenericScriptService.Attribute();
            att2.name = "blobUUID";
            att2.value = blobUUID;
            atts.Add(att2);

            GenericScriptService.Attribute att3 = new GenericScriptService.Attribute();
            att3.name = "action";
            att3.value = "ARCHIVO_B64";
            atts.Add(att3);

            GenericScriptService.Attribute att4 = new GenericScriptService.Attribute();
            att4.name = "scriptName";
            att4.value = scriptName;
            atts.Add(att4);

            return execute(atts, credentials);
        }
        private string GetAllRequestParam(GenericScriptService.Attribute[] atts)
        {
            string allAttributes = "";
            foreach (GenericScriptService.Attribute item in atts)
            {
                allAttributes += "{" + item.name + ":" + item.value + "},";
            }
            if (allAttributes.Length > 1)
                allAttributes = allAttributes.Substring(1, allAttributes.Length - 2);

            if (allAttributes.Length > MAX_LONG_RESPONSE)
            {
                allAttributes = allAttributes.Substring(0, MAX_LONG_RESPONSE) + ",...";
            }

            return allAttributes;
        }
        private bool Rintentar(String mensaje)
        {
            bool ok = false;
            mensaje = mensaje.ToUpper();
            //nested exception is javax.transaction.RollbackException: ARJUNA016053: Could not commit transaction.
            //an unexpected exception prevented the connection from being created.please refer to server logs for details.
            //EMPLOYEE NOT AN INCUMBENT OF THIS POSITION
            //JTA transaction unexpectedly rolled back(maybe due to a timeout)
            //The operation has timed out
            //The remote name could not be resolved: 'prd-p02-col.ellipsehosting.com'
            //The request failed with HTTP status 502: Proxy Error.
            //The underlying connection was closed: An unexpected error occurred on a receive.
            if ((mensaje.IndexOf("NOT AN INCUMBENT") > 0) ||
                (mensaje.IndexOf("COULD NOT BE RESOLVED") > 0) ||
                (mensaje.IndexOf("ROLLBACKEXCEPTION") > 0) ||
                (mensaje.IndexOf("UNEXPECTED EXCEPTION") > 0) ||
                (mensaje.IndexOf("UNEXPECTEDLY ROLLED BACK") > 0) ||
                (mensaje.IndexOf("FAILED WITH HTTP STATUS") > 0) ||
                (mensaje.IndexOf("CONNECTION WAS CLOSED") > 0) ||
                (mensaje.IndexOf("UNDERLYING CONNECTION") > 0) ||
                (mensaje.IndexOf("TIMED OUT") > 0))
            {
                ok = true;
            }
            // FUTURO:
            // Object reference not set to an instance of an object.
            // Operacion no valida
            // Unable to execute script
            //  (mensaje.IndexOf("OBJECT REFERENCE NOT SET") > 0) ||
            //  (mensaje.IndexOf("OPERACION NO VALIDA") > 0) ||
            //  (mensaje.IndexOf("UNABLE TO EXECUTE") > 0) ||
            return ok;
        }
        public static string GetRequestBody()
        {
            var bodyText = "";
            try
            {
                var bodyStream = new StreamReader(HttpContext.Current.Request.InputStream);
                bodyStream.BaseStream.Seek(0, SeekOrigin.Begin);
                bodyText = bodyStream.ReadToEnd();
            } catch (Exception)
            {

            }
            return bodyText;
        }

        public static string GetRequestHeader(string headerParam)
        {
            string headerText = null;

            try
            {
                headerText = HttpContext.Current.Request.Headers[headerParam];
            }
            catch (Exception)
            {
                headerText = null;
            }

            return headerText;
        }

        private List<GenericScriptService.Attribute> ConvertParamsToEllipse(JObject json)
        {
            List<GenericScriptService.Attribute> atts = new List<GenericScriptService.Attribute>();

            var dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(json.ToString(Formatting.None));
            foreach (var item in dictionary)
            {
                var key = item.Key;
                var value = item.Value;
                GenericScriptService.Attribute att = new GenericScriptService.Attribute();
                att.name = key.ToString();
                if (value != null)
                {
                    att.value = value.ToString();
                }
                else
                {
                    att.value = "";
                }

                atts.Add(att);
            }
            return atts;
        }
        private string GetTimeValue(string timeValue)
        {
            string[] timePart = timeValue.Split(' ');
            string result = "0";
            try
            {
                double number = Double.Parse(timePart[0], CultureInfo.CreateSpecificCulture("en-AU")) * 1000;
                result = number.ToString();
                previousTimeServer = result;
            }
            catch (Exception)
            {
                result = previousTimeServer;
            }

            return result;
        }
        private string GetParamValue(JObject json, string parameter)
        {
            Dictionary<string, object> dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(json.ToString(Formatting.None));
            try
            {
                return dictionary[parameter].ToString();
            }
            catch (Exception)
            {
                return "";
            }
        }
        private string GetParamValue(GenericScriptSearchParam paramSearch, string parameter)
        {
            try
            {
                GenericScriptService.Attribute att = Array.Find(paramSearch.customAttributes, element => element.name.Equals(parameter));
                return att.value;
            }
            catch (Exception)
            {
                return "";
            }
        }
        private string GetParamValue(GenericScriptService.Attribute[] attributes, string parameter)
        {
            try
            {
                GenericScriptService.Attribute att = Array.Find(attributes, element => element.name.Equals(parameter));
                return att.value;
            }
            catch (Exception)
            {
                return "";
            }
        }
        /*private string GetParamValue(Util.Attribute[] attributes, string parameter)
        {
            try
            {
                Util.Attribute att = Array.Find(attributes, element => element.name.Equals(parameter));
                return att.value;
            }
            catch (Exception)
            {
                return "";
            }
        }
        */
        private string GetParamValue(List<EllRow> ellRows, string parameter)
        {
            try
            {
                foreach (EllRow ellRow in ellRows)
                {
                    Util.Attribute att = Array.Find(ellRow.atts.ToArray(), element => element.name.Equals(parameter));
                    if (att != null)
                        return att.value;
                }
            }
            catch (Exception)
            {
                return "";
            }

            return "";
        }

        private List<Filelog> GetFileLogs(DateTime filterLogDateFrom, DateTime filterLogDateTo)
        {
            List<Filelog> logFiles = new List<Filelog>();
            string baseDirectory = HttpContext.Current.Server.MapPath(".") + "\\";
            baseDirectory = baseDirectory.Replace("api\\log", "");

            string baseDirectoryFilename = "";
            string logFilePattern = "";
            string logDirectory = "";

            List<FileTarget> files = LogManager.Configuration?
                .AllTargets
                .OfType<FileTarget>()
                .ToList();
            
            foreach (FileTarget file in files)
            {
                string relativePath = @file.ArchiveFileName.ToString().Replace("'", "");
                baseDirectoryFilename = Path.GetFullPath(baseDirectory +  relativePath.Replace("\\\\", "\\"));
                logFilePattern = Path.GetFileName(baseDirectoryFilename);
                logDirectory = Directory.GetParent(baseDirectoryFilename).FullName;
                Info("LOG DIRECTORY " + logDirectory);
                Info("BASEDIRECTORY " + baseDirectory);
                
                foreach (string fileLog in Directory.GetFiles(logDirectory))
                {
                    DateTime fileDate = File.GetCreationTime(fileLog);
                    if (
                        (DateTime.Compare(fileDate.Date, filterLogDateFrom.Date) == 1 || DateTime.Compare(fileDate.Date, filterLogDateFrom.Date) == 0) &&
                        (DateTime.Compare(fileDate.Date, filterLogDateTo.Date) < 0 || DateTime.Compare(fileDate.Date, filterLogDateTo.Date) == 0) 
                       )
                       
                    {
                        Filelog log = new Filelog();
                        log.fullName = fileLog;
                        log.folderName = logDirectory;
                        log.fileName = Path.GetFileName(fileLog);
                        logFiles.Add(log);
                    }
                }
            }

            return logFiles;
        }

        private string GetFileFromName(string fileName)
        {
            List<Filelog> logFiles = new List<Filelog>();
            string baseDirectory = HttpContext.Current.Server.MapPath(".") + "\\";
            baseDirectory = baseDirectory.Replace("api\\log", "");
            string baseDirectoryFilename = "";
            string logFilePattern = "";
            string logDirectory = "";

            List<FileTarget> files = LogManager.Configuration?
                .AllTargets
                .OfType<FileTarget>()
                .ToList();

            foreach (FileTarget file in files)
            {
                string relativePath = @file.ArchiveFileName.ToString().Replace("'", "");
                baseDirectoryFilename = Path.GetFullPath(baseDirectory + relativePath.Replace("\\\\", "\\"));
                logFilePattern = Path.GetFileName(baseDirectoryFilename);
                logDirectory = Directory.GetParent(baseDirectoryFilename).FullName;

                return logDirectory + "\\" + fileName;
            }

            return null;
        }

        private string GetParamValue(GenericScriptServiceResult[] paramResults, string parameter)
        {
            try
            {
                foreach (GenericScriptServiceResult paramResult in paramResults)
                {
                    GenericScriptService.Attribute att = Array.Find(paramResult.genericScriptDTO.customAttributes, element => element.name.Equals("json"));
                    if (att != null)
                    {
                        JObject json = JObject.Parse(att.value);
                        return GetParamValue(json, parameter);
                    }
                    else
                    {
                        att = Array.Find(paramResult.genericScriptDTO.customAttributes, element => element.name.Equals(parameter));
                        if (att != null)
                            return att.value;
                    }
                }
                return "";
            }
            catch (Exception)
            {
                return "";
            }
        }
        /*private string GetResponseValue(GenericScriptSearchParam paramSearch, string parameter)
        {
            try
            {
                GenericScriptService.Attribute att = Array.Find(paramSearch.customAttributes, element => element.name.Equals(parameter));
                return att.value;
            }
            catch (Exception)
            {
                return "";
            }
        }*/
        // para escribir en el archivo
        private void Info(string text)
        {
            string trace = "N";

            try
            {
                trace = WebConfigurationManager.AppSettings["Trace"];
            }
            catch (Exception)
            {
                trace = "N";
            }

            if (trace != null)
            {
                if (trace.Equals("Y"))
                {
                    log.Info(versionAPI + ";" + text.Replace("\r\n", " ").Replace("\n", " "));
                }
            }
        }

    }

    internal class CDDIntegration
    {
        private string initialConfig;

        public CDDIntegration(string initialConfig)
        {
            this.initialConfig = initialConfig;
        }
    }
}