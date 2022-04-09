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
using log4net;
using Newtonsoft.Json;
using System.Globalization;
/* Historia
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
        readonly string versionAPI = "v2.14";
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        private static readonly string formatDate = "yyyy-MM-dd HH:mm:ss";
        private static readonly int MAX_LONG_RESPONSE = 600;
        //formatDate

        [HttpGet]
        [Route("api/values")]
        public IEnumerable<string> Get()
        {
            return new string[] { WebConfigurationManager.AppSettings["EllService"], "App Matriz API Versión " + versionAPI + " ... hora del servidor : " + DateTime.Now.ToString() };
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

        [AllowAnonymous]
        [HttpPost]
        [Route("api/values/monitor")]
        public string monitor([FromBody] JObject data)
        {
            string sql = "";
            //1. Leer el XML -> Se lee la configuracion del web.config donde estan las credenciales de la base de datos.
            //2. Obtener un token con la tupla Ellipse user, pass, pos, dstr -> Se utilizara el usuario integracion para realizar el llamado autonomo
            //3. Llamar al servicio IMO_ACTUALIZAR_MSF010 usando el request del punto 5
            Credentials credentials = new Credentials();
            credentials.username = WebConfigurationManager.AppSettings["EllipseUsername"];
            credentials.password = WebConfigurationManager.AppSettings["EllipsePassword"];
            credentials.district = WebConfigurationManager.AppSettings["EllipseDistrict"];
            credentials.position = WebConfigurationManager.AppSettings["EllipsePosition"];
            OperationContext oc = new OperationContext();
            oc.district = credentials.district;
            oc.position = credentials.position;

            GenericScriptService.GenericScriptService proxySheet = new GenericScriptService.GenericScriptService();
            proxySheet.Url = WebConfigurationManager.AppSettings["EllService"] + "GenericScriptService";

            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam = new GenericScriptService.GenericScriptSearchParam();
            genericScriptSearchParam.customAttributes = new GenericScriptService.Attribute[]
            {
                CreateAttribute("scriptName","coeimo"),
                CreateAttribute("action","IMO_ACTUALIZAR_MSF010")
            };

            GenericScriptService.GenericScriptDTO genericScriptDTO = new GenericScriptService.GenericScriptDTO();
            genericScriptDTO.customAttributes = genericScriptSearchParam.customAttributes;
            genericScriptDTO.scriptName = "coeimo";
            string serverTime = "";
            try
            {
                Util.HttpResponse<List<Util.EllRow>> response = sendGeneric(oc, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);
                //Recibir el response: IF code == 200 
                //Obtener el “serverTime”
                if (response.data[0].atts[0].name.ToLower().Contains("json"))
                {
                    JObject json = JObject.Parse(response.data[0].atts[0].value);
                    serverTime = GetParamValue(json, "serverTime");
                } else
                {
                    foreach (Util.EllRow rows in response.data)
                    {
                        foreach (Util.Attribute att in rows.atts) 
                        { 
                            if (att.name.Equals("serverTime"))
                            {
                                serverTime = att.value;
                            }
                        }
                    }
                }

                //Conectarse a Oracle con la tupla DBname, user, pass, ip, puerto
                //Ejecutar el comando SQL del punto 3
                IConnection conn = new ConnectionOracleImpl();
                sql = "select table_desc, last_mod_date, last_mod_time from msf010 where table_type = 'HOST' and table_code = 'REPL'";
                Dictionary<int, Dictionary<string, object>> dataQuery = conn.GetQueryResultSet(sql);
                string lastModDate = dataQuery[0]["last_mod_date"].ToString();
                string lastModtime = dataQuery[0]["last_mod_time"].ToString();

                DateTime replTime = DateTime.ParseExact(lastModDate + lastModtime, "yyyyMMddHHmmss", CultureInfo.InvariantCulture);
                DateTime serverDateTime = DateTime.ParseExact(serverTime, "yyyy/MM/ddTHHmm", CultureInfo.InvariantCulture);

                //responseTime = serverTime – lastModDate / time
                TimeSpan span = replTime - serverDateTime;

                //Llamar al servicio IMO_STATUS_MSF010 usando el request del punto 6
                genericScriptSearchParam.customAttributes = new GenericScriptService.Attribute[]
                {
                    CreateAttribute("scriptName","coeimo"),
                    CreateAttribute("action","IMO_STATUS_MSF010"),
                    CreateAttribute("responseTime",span.TotalSeconds.ToString())
                };
                sendGeneric(oc, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);
            }
            catch (Exception )
            {

            }
            return "";
        }
        
        public GenericScriptService.Attribute CreateAttribute(string name, string value)
        {
            GenericScriptService.Attribute att = new GenericScriptService.Attribute();
            att.name = name;
            att.value = value;

            return att;
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

                return GetDefaultDistrictByGroovy(userToFind, credentials);
            }

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
                    credentials.username + ";" +
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
                return GetDefaultPositionByGroovy(userToFind, credentials);
            }
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
                    credentials.username + ";" +
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

            return execute(atts, credentials);
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

        [Authorize]
        [HttpPost]
        [Route("api/values/generic")]
        public Util.HttpResponse<List<Util.EllRow>> generic([FromBody] Util.BodyParams value)
        {
            DateTime intialDate = DateTime.Now;
            Credentials credentials = new Credentials();
            var identity = (ClaimsIdentity)User.Identity;
            string allAttributes = "";
            string scriptActionParam = "";
            string scriptNameParam = "";
            string timeParam = "";

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

                    allAttributes += "{" + item.name + ":" + item.value + "}, ";
                }

                genericScriptDTO.scriptName = value.script_name;
                genericScriptDTO.customAttributes = atts.ToArray();
                genericScriptSearchParam.customAttributes = atts.ToArray();

                
                result = sendGeneric(opSheet, proxySheet, genericScriptSearchParam, genericScriptDTO, credentials);
                if (allAttributes.Length > MAX_LONG_RESPONSE)
                {
                    allAttributes = allAttributes.Substring(0, MAX_LONG_RESPONSE) + "...";
                }

                scriptActionParam = GetParamValue(atts.ToArray(), "action");
                scriptNameParam = GetParamValue(atts.ToArray(), "scriptName");
                try
                {
                    timeParam = GetParamValue(result.data, "time");
                } catch (Exception)
                {
                    timeParam = "0";
                }

                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";" + 
                    scriptNameParam + ";" + 
                    scriptActionParam + ";OK;" +
                    spanMS + ";" +
                    GetTimeValue(timeParam) + ";" +
                    credentials.username + ";" +
                    credentials.district + ";" +
                    opSheet.position + ";" +
                    allAttributes);

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
                    credentials.username + ";" +
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
                            credentials.username + ";" +
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
                            credentials.username + ";" +
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
                (mensaje.IndexOf("TIMED OUT") > 0) )
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
            var bodyStream = new StreamReader(HttpContext.Current.Request.InputStream);
            bodyStream.BaseStream.Seek(0, SeekOrigin.Begin);
            var bodyText = bodyStream.ReadToEnd();
            return bodyText;
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
            string time = "";
            Credentials credentials = new Credentials();
            var identity = (ClaimsIdentity)User.Identity;
            JObject json = null;

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
                string resultado = "[RESULTADO]";
                if (result.data[0].atts[0].name.ToLower().Contains("json"))
                {
                    json = JObject.Parse(result.data[0].atts[0].value);
                }
                else
                {
                    resultado = "Groovy no contiene atributo de salida json esperado";
                    json = JObject.FromObject(new
                    {
                        error = resultado
                    });
                }
                if (allAttributes.Length > MAX_LONG_RESPONSE)
                {
                    allAttributes = allAttributes.Substring(0, MAX_LONG_RESPONSE);
                }
                
                time = GetParamValue(json, "time");

                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";" + scriptNameParam + ";" + actionPparam + ";OK;" +
                    spanMS + ";" + GetTimeValue(time) + ";" +
                    credentials.username + ";" +
                    credentials.district + ";" +
                    opSheet.position + ";" +
                    allAttributes + ";" + resultado);
            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";" + scriptNameParam + ";" + actionPparam + ";E6;" +
                    spanMS + ";0;" +
                    credentials.username + ";" +
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
                } else
                {
                    att.value = "";
                }

                atts.Add(att);
            }
            return atts;
        }

        private string GetTimeValue(string timeValue)
        {
            string[] timePart= timeValue.Split(' ');
            string result = "0";
            try
            {
                double number = Double.Parse(timePart[0], CultureInfo.CreateSpecificCulture("en-AU")) * 1000;
                result = number.ToString();
            } catch (Exception)
            {
                result = "-1";
            }

            return result;
        }

        private string GetParamValue(JObject json, string parameter)
        {
            Dictionary<string, object> dictionary = JsonConvert.DeserializeObject<Dictionary<string, object>>(json.ToString(Formatting.None));
            try
            {
                return dictionary[parameter].ToString();
            } catch (Exception)
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
            } catch (Exception)
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


        private string GetParamValue(Util.Attribute[] attributes, string parameter)
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

        private string GetParamValue(List<EllRow> ellRows, string parameter)
        {
            try
            {
                foreach (EllRow ellRow in ellRows) {
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

        private string GetParamValue(GenericScriptServiceResult[] paramResults, string parameter)
        {
            try
            {
                foreach (GenericScriptServiceResult paramResult in paramResults) {
                    GenericScriptService.Attribute att = Array.Find(paramResult.genericScriptDTO.customAttributes, element => element.name.Equals("json"));
                    if (att != null)
                    {
                        JObject json = JObject.Parse(att.value);
                        return GetParamValue(json, parameter);
                    } else
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
        

        private string GetResponseValue(GenericScriptSearchParam paramSearch, string parameter)
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
                    log.Info(versionAPI + ";" + text);
                    //LogManager.Flush(500);
                }
            }
        }

        private Util.HttpResponse<List<Util.EllRow>> sendGeneric(GenericScriptService.OperationContext opSheet,
            GenericScriptService.GenericScriptService proxySheet,
            GenericScriptService.GenericScriptSearchParam genericScriptSearchParam,
            GenericScriptService.GenericScriptDTO genericScriptDTO,
            Credentials credentials)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            string errors = "";
            string scriptNameParam = GetParamValue(genericScriptSearchParam, "scriptName");
            string scriptActionParam = GetParamValue(genericScriptSearchParam, "action");

            EllipseWebServicesClient.ClientConversation.username = credentials.username;
            EllipseWebServicesClient.ClientConversation.password = credentials.password;

            
            DateTime intialDate = DateTime.Now;
            GenericScriptService.GenericScriptServiceResult[] genericScriptServiceResults = proxySheet.executeForCollection(opSheet, genericScriptSearchParam, genericScriptDTO);
            Util.HttpResponse<List<Util.EllRow>> result = new Util.HttpResponse<List<Util.EllRow>>();
            List<Util.EllRow> data = new List<Util.EllRow>();
            //bool redirect = false;

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
                    
                    Info(intialDate.ToString(formatDate) + ";" + scriptNameParam + ";" + scriptActionParam + ";OK;" +
                        "0;" + GetTimeValue(timeParam) + ";" + 
                        credentials.username + ";" +
                        credentials.district + ";" +
                        opSheet.position + ";" +
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

            result.redirect = null;
            result.message = "Generic se ejecuto Correctamente";
            result.data = data;
            result.success = true;

            return result;
        }

        /*[Authorize(Roles = "admin")]
        [HttpGet]
        [HttpGet]
        [Route("api/values/authorize")]
        public IHttpActionResult GetForAdmin()
        {
            var identity = (ClaimsIdentity)User.Identity;
            var roles = identity.Claims.Where(c => c.Type == ClaimTypes.Role).Select(c => c.Value);
            return Ok("Hello " + identity.Name + " Role " + string.Join(",", roles.ToList()));
        }*/

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
                try
                {

                    GenericScriptServiceResult[] results = proxySheet.executeForCollection(opSheet, genericScriptSearchParam, genericScriptDTO);
                    string errors = "";
                    foreach (GenericScriptServiceResult genericScriptServiceResult in results)
                    {
                        
                        String name = genericScriptServiceResult.genericScriptDTO.customAttributes[0].value;
                        String value = genericScriptServiceResult.genericScriptDTO.customAttributes[1].value;

                        row.atts.Add(new Util.Attribute() { name = name, value = value });

                        foreach (Error error in genericScriptServiceResult.errors)
                        {
                            errors = errors + error.messageText + " - ";
                        }

                    }

                    TimeSpan span = DateTime.Now - intialDate;
                    long spanMS = (long)span.TotalMilliseconds;
                    Info(intialDate.ToString(formatDate) + ";execute;OK;" +
                        spanMS + ";0;" +
                        credentials.username + ";" +
                        credentials.district + ";" +
                        opSheet.position + ";" +
                        "Errors=" + errors);

                    data.Add(row);
                    return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "success", redirect = false, success = true };
                }
                catch (Exception ex)
                {
                    TimeSpan span = DateTime.Now - intialDate;
                    long spanMS = (long)span.TotalMilliseconds;
                    Info(intialDate.ToString(formatDate) + ";execute;E7;" +
                        spanMS + ";0;" +
                        credentials.username + ";" +
                        credentials.district + ";" +
                        credentials.position + ";" +
                        ex.Message + ";\n" + ex.StackTrace);
                    row.atts.Add(new Util.Attribute() { name = "ERROR", value = "ERROR AL EJECUTAR EL PROCEDIMIENTO " + ex.Message });
                    data.Add(row);
                    return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "no success", redirect = false, success = false };
                }
            }
            catch (Exception ex)
            {
                TimeSpan span = DateTime.Now - intialDate;
                long spanMS = (long)span.TotalMilliseconds;
                Info(intialDate.ToString(formatDate) + ";execute;E8;" +
                    spanMS + ";0;" +
                    credentials.username + ";" +
                    credentials.district + ";" +
                    credentials.position + ";" +
                    ex.Message + ";\n" + ex.StackTrace);
                row.atts.Add(new Util.Attribute() { name = "ERROR", value = "ERROR AL EJECUTAR EL PROCEDIMIENTO" });
                data.Add(row);
                return new Util.HttpResponse<List<Util.EllRow>>() { data = data, message = "no success", redirect = false, success = false };
            }
        }

    }

}
