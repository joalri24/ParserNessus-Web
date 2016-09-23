using ParserNessus.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Mvc;

namespace ParserNessus.Controllers
{
    public class UploadController : Controller
    {

        //-----------------------------------------------------------------------------------
        // Constantes
        //-----------------------------------------------------------------------------------

        const string REPORT_NAME_TAG = "<Report name=\"";
        const string REPORT_END_TAG = "</Report>";
        const string REPORT_HOST_TAG = "<ReportHost";
        const string REPORT_HOST_END_TAG = "</ReportHost>";
        const string HOST_PROPERTIES_END_TAG = "</HostProperties>";
        const string HOST_END_TAG = "<tag name=\"HOST_END\">";
        const string HOST_START_TAG = "<tag name=\"HOST_START\">";
        const string HOST_OS_TAG = "<tag name=\"operating-system\">";
        const string HOST_MAC_TAG = "<tag name=\"mac-address\">";
        const string HOST_IP_TAG = "<tag name=\"host-ip\">";
        const string HOST_NETBIOS_TAG = "<tag name=\"netbios-name\">";
        const string REPORT_ITEM_TAG = "<ReportItem";
        const string REPORT_ITEM_END_TAG = "</ReportItem>";
        const string ITEM_BID_TAG = "<bid>";
        const string ITEM_CVE_TAG = "<cve>";
        const string ITEM_EXPLOIT_AVAILABLE_TAG = "<exploit_available>";
        const string ITEM_CVSS_SCORE_TAG = "<cvss_temporal_score>";
        const string ITEM_RISK_FACTOR_TAG = "<risk_factor>";
        const string ITEM_PLUGIN_NAME_TAG = "<plugin_name>";
        const string ITEM_SYNOPSIS_TAG = "<synopsis>";
        const string ITEM_SOLUTION_TAG = "<solution>";
        const string ITEM_SEE_ALSO_TAG = "<see_also>";
        const string ITEM_XREF_TAG = "<xref>";
        const string ITEM_DESCRIPTION_TAG = "<description>";
        const string END_TAG = "</";

        const string ENCABEZADO_VULNERABILIDADES = "Vulnerabilidad;Descripción;Solución;Ip;Puerto;Nombre;Protocolo;Severidad;Explotable;cve;bid;Puntaje cvss;Nombre del plug-in;Info adicional;xref";
        const string ENCABEZADO_SINOPSIS = "Vulnerabilidad";
        const string ENCABEZADO_DESCRIPCION = "Descripción";
        const string ENCABEZADO_SOLUCION = "Solución";
        const string ENCABEZADO_IP = "Dirección IP";
        const string ENCABEZADO_PUERTO = "Puerto";
        const string ENCABEZADO_NET_BIOS_NAME = "Nombre";
        const string ENCABEZADO_PROTOCOLO = "Protocolo";
        const string ENCABEZADO_SEVERIDAD = "Severidad";
        const string ENCABEZADO_EXPLOIT_AVAILABLE = "Explotable";
        const string ENCABEZADO_CVE = "cve";
        const string ENCABEZADO_BID = "bid";
        const string ENCABEZADO_CVSS_SCORE = "Puntaje cvss";
        const string ENCABEZADO_PLUG_IN_NAME = "Nombre del plug-in";
        const string ENCABEZADO_SEE_ALSO = "Información adicional";
        const string ENCABEZADO_XREF = "xref";
        const string ENCABEZADO_MAC = "Dirección mac";
        const string ENCABEZADO_SISTEMA_OPERATIVO = "Sistema operativo";
        const char SEPARADOR = ';';

        const string UPLOAD_DIR = "~/App_Data/Upload";
        const string OUT_DIR = "~/App_Data/Out";


        //-----------------------------------------------------------------------------------
        // Actions
        //-----------------------------------------------------------------------------------

        // GET: Upload
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// Uploads a file onto the server.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Upload(HttpPostedFileBase file, bool NoSeverity = false)
        {
            //System.Diagnostics.Debug.WriteLine(NoSeverity);
            if (file.ContentLength > 0)
            {
                var fileName = Path.GetFileName(file.FileName);
                var path = Path.Combine(Server.MapPath(UPLOAD_DIR), fileName);
                file.SaveAs(path);
                
                // Reads the uploaded file and generates the cvs file.
                AuxReport reporte = ReadFile(path,NoSeverity);
                string newPath = WriteCsvFile(reporte); 

                return RedirectToAction("Download", new { path = newPath, fileName = reporte.Report.Name + ".cvs" });
            }

            return View("Index");

        }

        // GET Upload/Download?filename=name
        /// <summary>
        /// Return a file to the user. Displays the download option.
        /// </summary>
        /// <param name="FileName"></param>
        /// <returns></returns>
        public FileResult Download(string path, string fileName)
        {
            byte[] fileBytes = System.IO.File.ReadAllBytes(path);
            return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
        }


        //-----------------------------------------------------------------------------------
        // Methods
        //-----------------------------------------------------------------------------------

        /// <summary>
        /// Reads the file line by line and extracts the data.
        /// Creates a Report object, creates a host object for each host in the  
        /// report and vulnerability object for each host's vulnerability.
        /// Returns an AuxReport object with the relevant data of the file
        /// </summary>
        /// <returns>Returns an AuxReport object with the relevant data of the file</returns>
        /// <param name="fileName"></param>
        /// <param name="NoSeverity">Says if items with no severity are going to be read</param>
        private AuxReport ReadFile(string fileName, bool ReadNoSeverityItems)
        {

            AuxReport reporte = new AuxReport();
            string[] lineas = System.IO.File.ReadAllLines(fileName);
            int numLinea = 0;
            string reportName = "";

            // Iterar hasta que aparezca el tag "<Report name"
            while (!lineas[numLinea].Contains(REPORT_NAME_TAG))
                numLinea++;

            // Leer el nombre del reporte.
            // Eje: <Report name="TG" xmlns:cm="http://www.nessus.org/cm">
            reportName = Regex.Split(lineas[numLinea], REPORT_NAME_TAG)[1].Split('"')[0];
            reporte.Report.Name = reportName;

            // Iterar hasta el final del reporte: mientras la línea no contenga "</Report>":
            while (!lineas[numLinea].Contains(REPORT_END_TAG))
            {
                // Cuando encuentra un ReportHost, lee su información.
                if (lineas[numLinea].Contains(REPORT_HOST_TAG))
                {
                    AuxHost host = new AuxHost();
                    string hostname = "";
                    string hostEnd = "";
                    string hostStart = "";
                    string hostIp = "";
                    string operativeSystem = "";
                    string mac = "";
                    string netbiosName = "";

                    // Obtiene el nombre del host.
                    hostname = Regex.Split(lineas[numLinea], "name=\"")[1].Split('"')[0];  //<ReportHost name="10.1.4.180"><HostProperties>                    
                    numLinea++;

                    // Leer las propiedades del host
                    while (!lineas[numLinea].Contains(HOST_PROPERTIES_END_TAG))
                    {
                        // Obtener el HOST_END
                        if (lineas[numLinea].Contains(HOST_END_TAG))
                        {
                            // <tag name="HOST_END">Thu Jul 28 14:46:10 2016</tag>
                            hostEnd = Regex.Split(lineas[numLinea], HOST_END_TAG)[1];
                            hostEnd = Regex.Split(hostEnd, END_TAG)[0];
                        }

                        // Obtener el HOST_START
                        if (lineas[numLinea].Contains(HOST_START_TAG))
                        {
                            // <tag name="HOST_START">Thu Jul 28 14:46:10 2016</tag>
                            hostStart = Regex.Split(lineas[numLinea], HOST_START_TAG)[1];
                            hostStart = Regex.Split(hostStart, END_TAG)[0];
                        }

                        // Obtener el host-ip
                        if (lineas[numLinea].Contains(HOST_IP_TAG))
                        {
                            // <tag name="host-ip">10.1.4.203</tag>
                            hostIp = Regex.Split(lineas[numLinea], HOST_IP_TAG)[1];
                            hostIp = Regex.Split(hostIp, END_TAG)[0];
                        }

                        // Obtener el netbios_name
                        if (lineas[numLinea].Contains(HOST_NETBIOS_TAG))
                        {
                            // <tag name = "netbios-name">HMERCADO</tag>
                            netbiosName = Regex.Split(lineas[numLinea], HOST_NETBIOS_TAG)[1];
                            netbiosName = Regex.Split(netbiosName, END_TAG)[0];
                        }

                        /** Obtiene el sistema operativo.
                         *
                         *   Eje 1:
                         *   <tag name="operating-system">AIX 4.3.2
                         *   AIX 5.2
                         *   CatalystOS 6.3
                         *   VAX / VMS 7.1 </tag> 
                         *
                         *   Eje 2:
                         *   <tag name="operating-system">RICOH Printer</tag> 
                         */
                        if (lineas[numLinea].Contains(HOST_OS_TAG))
                        {
                            while (true)  // Recorre todas las líneas del campo
                            {
                                string os = "";
                                // Existen diferentes casos. 
                                // 1. El tag de inicio y el tag de final están en la misma línea
                                // 2. Únicamente el tag de inicio está en la línea.
                                // 3. Únicamente el tag de final está en la línea.
                                // 4. La línea no tiene tags.

                                // 1. Eje: <tag name="operating-system">RICOH Printer</tag>
                                if (lineas[numLinea].Contains(HOST_OS_TAG) && lineas[numLinea].Contains(END_TAG))
                                {
                                    os = Regex.Split(lineas[numLinea], HOST_OS_TAG)[1];
                                    os = Regex.Split(os, END_TAG)[0];
                                    operativeSystem = operativeSystem + os;
                                    break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                }

                                // 3. Eje: VAX / VMS 7.1 </tag>
                                else if (lineas[numLinea].Contains(END_TAG))
                                {
                                    os = Regex.Split(lineas[numLinea], END_TAG)[0];
                                    operativeSystem = operativeSystem + " " + os;
                                    break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                }

                                // 2. Eje: <tag name="operating-system">AIX 4.3.2
                                else if (lineas[numLinea].Contains(HOST_OS_TAG))
                                {
                                    os = Regex.Split(lineas[numLinea], HOST_OS_TAG)[1];
                                    operativeSystem = operativeSystem + os;
                                }

                                // 4. Eje: AIX 5.2
                                else
                                    operativeSystem = operativeSystem + " " + lineas[numLinea];

                                numLinea++;
                            }
                        }

                        /** Obtiene la dirección mac.
                         *
                         *   Eje 1:
                         *   <tag name="mac-address">00:0c:29:71:87:10</tag>
                         *
                         *   Eje 2:
                         *   <tag name="mac-address">00:00:00:00:00:00
                         *   00:22:57:b4:91:75
                         *   74820 00:0e:11:14:e9:2e</tag> 
                         */
                        if (lineas[numLinea].Contains(HOST_MAC_TAG))
                        {

                            while (true) // Recorre todas las líneas del campo
                            {
                                // Existen diferentes casos. 
                                // 1. El tag de inicio y el tag de final están en la misma línea
                                // 2. Únicamente el tag de final está en la línea.
                                // 3. Únicamente el tag de inicio está en la línea.
                                // 4. La línea no tiene tags.
                                string temp = "";

                                // 1. Eje: <tag name="mac-address">00:0c:29:71:87:10</tag>
                                if (lineas[numLinea].Contains(HOST_MAC_TAG) && lineas[numLinea].Contains(END_TAG))
                                {
                                    temp = Regex.Split(lineas[numLinea], HOST_MAC_TAG)[1];
                                    temp = Regex.Split(temp, END_TAG)[0];
                                    mac = mac + temp;
                                    break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                }

                                // 2. Eje: 74820 00:0e:11:14:e9:2e</tag>
                                else if (lineas[numLinea].Contains(END_TAG))
                                {
                                    temp = Regex.Split(lineas[numLinea], END_TAG)[0];
                                    mac = mac + " " + temp;
                                    break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                }

                                // 3. Eje: <tag name="mac-address">00:00:00:00:00:00
                                else if (lineas[numLinea].Contains(HOST_MAC_TAG))
                                {
                                    temp = Regex.Split(lineas[numLinea], HOST_MAC_TAG)[1];
                                    mac = mac + temp;
                                }

                                // 4. Eje: 00:22:57:b4:91:75
                                else
                                    mac = mac + " " + lineas[numLinea];

                                numLinea++;
                            }
                        }

                        numLinea++;
                    }

                    // Agrega la información al objeto host y lo agrega a la lista de hosts
                    host.Host.HostName = hostname;
                    host.Host.HostEnd = hostEnd;
                    host.Host.HostStart = hostStart;
                    host.Host.OperativeSystem = operativeSystem;
                    host.Host.HostIp = hostIp;
                    host.Host.Mac = mac;
                    host.Host.NetBiosName = netbiosName;
                    reporte.Hosts.Add(host);

                    // Iterar hasta que encuentra un tag de fin del host.
                    while (!lineas[numLinea].Contains(REPORT_HOST_END_TAG))
                    {
                        // Si encuentra un ReportItem, leer su información.
                        if (lineas[numLinea].Contains(REPORT_ITEM_TAG))
                        {
                            Vulnerability vulnerabilidad = new Vulnerability();
                            string puerto = "";
                            string protocolo = "";
                            int severidad = 0;
                            string bid = "";
                            string cve = "";
                            string exploitAvailable = "false";
                            string cvssTemporalScore = "";
                            string riskFactor = "";
                            string pluginName = "";
                            string sinopsis = "";
                            string solucion = "";
                            string seeAlso = "";
                            string xref = "";
                            string descripcion = "";

                            string strSeveridad = Regex.Split(lineas[numLinea], "severity=\"")[1];
                            strSeveridad = strSeveridad.Split('"')[0];
                            severidad = Convert.ToInt16(strSeveridad);

                            // Saca todos los items o únicamente aquellos con severidad mayor a 0 según la elección del usuario.
                            if (severidad > 0 || ReadNoSeverityItems)
                            {
                                // Extraer datos del campo
                                //Eje: <ReportItem port="1027" svc_name="dce-rpc" protocol="tcp" severity="2" pluginID="90510" pluginName="MS16-047: Security Update for SAM and LSAD Remote Protocols (3148527) (Badlock) (uncredentialed check)" pluginFamily="Windows">
                                puerto = Regex.Split(lineas[numLinea], "port=\"")[1];
                                puerto = puerto.Split('"')[0];

                                protocolo = Regex.Split(lineas[numLinea], "protocol=\"")[1];
                                protocolo = protocolo.Split('"')[0];

                                // Lee los campos dentro del report Item
                                while (!lineas[numLinea].Contains(REPORT_ITEM_END_TAG))
                                {
                                    // Leer el BID                                   
                                    if (lineas[numLinea].Contains(ITEM_BID_TAG))
                                    {
                                        // Eje: <bid>74013</bid>
                                        string temp = "";
                                        temp = Regex.Split(lineas[numLinea], ITEM_BID_TAG)[1];
                                        temp = Regex.Split(temp, END_TAG)[0];
                                        bid = (bid == "") ? bid + temp : bid + " " + temp;
                                    }

                                    // Leer el CVE
                                    if (lineas[numLinea].Contains(ITEM_CVE_TAG))
                                    {
                                        // Eje: <cve>CVE-2015-1635</cve>
                                        string temp = "";
                                        temp = Regex.Split(lineas[numLinea], ITEM_CVE_TAG)[1];
                                        temp = Regex.Split(temp, END_TAG)[0];
                                        cve = (cve == "") ? cve + temp : cve + " " + temp;
                                    }

                                    // Leer el Exploit available
                                    if (lineas[numLinea].Contains(ITEM_EXPLOIT_AVAILABLE_TAG))
                                    {
                                        // Eje: <exploit_available>true</exploit_available>
                                        exploitAvailable = Regex.Split(lineas[numLinea], ITEM_EXPLOIT_AVAILABLE_TAG)[1];
                                        exploitAvailable = Regex.Split(exploitAvailable, END_TAG)[0];
                                    }

                                    // Leer el cvss temporal score>
                                    if (lineas[numLinea].Contains(ITEM_CVSS_SCORE_TAG))
                                    {
                                        // Eje: <cvss_temporal_score>8.7</cvss_temporal_score>
                                        cvssTemporalScore = Regex.Split(lineas[numLinea], ITEM_CVSS_SCORE_TAG)[1];
                                        cvssTemporalScore = Regex.Split(cvssTemporalScore, END_TAG)[0];
                                    }

                                    // Leer el factor de riesgo
                                    if (lineas[numLinea].Contains(ITEM_RISK_FACTOR_TAG))
                                    {
                                        // Eje: <risk_factor>None</risk_factor>
                                        riskFactor = Regex.Split(lineas[numLinea], ITEM_RISK_FACTOR_TAG)[1];
                                        riskFactor = Regex.Split(riskFactor, END_TAG)[0];
                                    }

                                    // Leer el nombre del plug-in
                                    if (lineas[numLinea].Contains(ITEM_PLUGIN_NAME_TAG))
                                    {
                                        // Eje: <plugin_name>Service Detection</plugin_name>
                                        pluginName = Regex.Split(lineas[numLinea], ITEM_PLUGIN_NAME_TAG)[1];
                                        pluginName = Regex.Split(pluginName, END_TAG)[0];
                                    }

                                    // Leer la sinopsis
                                    if (lineas[numLinea].Contains(ITEM_SYNOPSIS_TAG))
                                    {
                                        // Eje: <synopsis>The remote web server does not return 404 error codes.</synopsis>
                                        sinopsis = Regex.Split(lineas[numLinea], ITEM_SYNOPSIS_TAG)[1];
                                        sinopsis = Regex.Split(sinopsis, END_TAG)[0];
                                    }

                                    // Leer el campo xref
                                    if (lineas[numLinea].Contains(ITEM_XREF_TAG))
                                    {
                                        // Eje: <xref>OSVDB:91162</xref>
                                        string temp = "";
                                        temp = Regex.Split(lineas[numLinea], ITEM_XREF_TAG)[1];
                                        temp = Regex.Split(temp, END_TAG)[0];
                                        xref = (xref == "") ? xref + temp : xref + " " + temp;
                                    }

                                    // Leer la solución
                                    if (lineas[numLinea].Contains(ITEM_SOLUTION_TAG))
                                    {
                                        /* Eje 1: "<solution>n/a</solution>"
                                         *
                                         * Eje 2:
                                         * <solution>- Force the use of SSL as a transport layer for this service if supported, or/and
                                         * 
                                         * - Select the &apos;Allow connections only from computers running Remote Desktop with Network Level Authentication&apos; setting if it is available.</solution>
                                         */
                                        while (true)  // Recorre todas las líneas del campo
                                        {

                                            // Existen diferentes casos. 
                                            // 1. El tag de inicio y el tag de final están en la misma línea
                                            // 2. Únicamente el tag de final está en la línea.
                                            // 3. Únicamente el tag de inicio está en la línea.
                                            // 4. La línea no tiene tags.

                                            string so = "";
                                            // 1. Eje: "<solution>n/a</solution>"
                                            if (lineas[numLinea].Contains(ITEM_SOLUTION_TAG) && lineas[numLinea].Contains(END_TAG))
                                            {
                                                so = Regex.Split(lineas[numLinea], ITEM_SOLUTION_TAG)[1];
                                                so = Regex.Split(so, END_TAG)[0];
                                                solucion = solucion + so;
                                                break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                            }

                                            // 2. Eje: setting if it is available.</solution>
                                            else if (lineas[numLinea].Contains(END_TAG))
                                            {
                                                so = Regex.Split(lineas[numLinea], END_TAG)[0];
                                                solucion = solucion + " " + so;
                                                break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                            }

                                            // 3. Eje: <solution>- Force the use of SSL as a transport layer
                                            else if (lineas[numLinea].Contains(ITEM_SOLUTION_TAG))
                                            {
                                                so = Regex.Split(lineas[numLinea], ITEM_SOLUTION_TAG)[1];
                                                solucion = solucion + so;
                                            }

                                            // 4. Eje: - Select the &apos;Allow connections only from computers running Remote Desktop
                                            else
                                                solucion = solucion + " " + lineas[numLinea];

                                            numLinea++;
                                        }
                                    }

                                    // Leer el campo de "see also" 
                                    if (lineas[numLinea].Contains(ITEM_SEE_ALSO_TAG))
                                    {
                                        /* Eje 1: <see_also>http://msdn.microsoft.com/en-us/library/dd304523.aspx</see_also>
                                         *
                                         * Eje 2:
                                         * <see_also>http://www.nessus.org/u?217a3666
                                         * http://cr.yp.to/talks/2013.03.12/slides.pdf
                                         * http://www.isg.rhul.ac.uk/tls/
                                         * http://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf</see_also>
                                         */
                                        while (true)  // Recorre todas las líneas del campo
                                        {
                                            // Existen diferentes casos. 
                                            // 1. El tag de inicio y el tag de final están en la misma línea
                                            // 2. Únicamente el tag de final está en la línea.
                                            // 3. Únicamente el tag de inicio está en la línea.
                                            // 4. La línea no tiene tags.

                                            string sa = "";
                                            // 1. Eje: <see_also>http://msdn.microsoft.com/en-us/library/dd304523.aspx</see_also>
                                            if (lineas[numLinea].Contains(ITEM_SEE_ALSO_TAG) && lineas[numLinea].Contains(END_TAG))
                                            {
                                                sa = Regex.Split(lineas[numLinea], ITEM_SEE_ALSO_TAG)[1];
                                                sa = Regex.Split(sa, END_TAG)[0];
                                                seeAlso = seeAlso + sa;
                                                break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                            }

                                            // 2. Eje: http://www.imperva.com/docs/HII_Attacking_SSL_when_using_RC4.pdf</see_also>
                                            else if (lineas[numLinea].Contains(END_TAG))
                                            {
                                                sa = Regex.Split(lineas[numLinea], END_TAG)[0];
                                                seeAlso = seeAlso + " " + sa;
                                                break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                            }

                                            // 3. Eje: <see_also>http://www.nessus.org/u?217a3666
                                            else if (lineas[numLinea].Contains(ITEM_SEE_ALSO_TAG))
                                            {
                                                sa = Regex.Split(lineas[numLinea], ITEM_SEE_ALSO_TAG)[1];
                                                seeAlso = seeAlso + sa;
                                            }

                                            // 4. Eje: http://cr.yp.to/talks/2013.03.12/slides.pdf
                                            else
                                                seeAlso = seeAlso + " " + lineas[numLinea];

                                            numLinea++;
                                        }
                                    }

                                    // Leer la descripción
                                    if (lineas[numLinea].Contains(ITEM_DESCRIPTION_TAG))
                                    {
                                        // Eje: 
                                        /* <description>According to the web server&apos;s banner, the version of HP System Management Homepage (SMH) hosted on the remote web server is prior to 7.2.6. It is, therefore, affected by multiple vulnerabilities, including remote code execution vulnerabilities, in several components and third-party libraries :
                                         *
                                         * - HP SMH (XSRF)
                                         * - libcurl
                                         * - OpenSSL</description>
                                         */
                                        while (true)  // Recorre todas las líneas del campo
                                        {
                                            // Existen diferentes casos. 
                                            // 1. El tag de inicio y el tag de final están en la misma línea
                                            // 2. Únicamente el tag de final está en la línea.
                                            // 3. Únicamente el tag de inicio está en la línea.
                                            // 4. La línea no tiene tags.

                                            string des = "";

                                            // 1. Eje: <description>The version of GlassFish Server running on the remote host is affected by an unspecified vulnerability in the Admin Console.</description>
                                            if (lineas[numLinea].Contains(ITEM_DESCRIPTION_TAG) && lineas[numLinea].Contains(END_TAG))
                                            {
                                                des = Regex.Split(lineas[numLinea], ITEM_DESCRIPTION_TAG)[1];
                                                des = Regex.Split(des, END_TAG)[0];
                                                descripcion = descripcion + des;
                                                break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                            }

                                            // 2. Eje: - OpenSSL</description>
                                            else if (lineas[numLinea].Contains(END_TAG))
                                            {
                                                des = Regex.Split(lineas[numLinea], END_TAG)[0];
                                                descripcion = descripcion + " " + des;
                                                break; // Termina el ciclo cuando encuentra el tag de cierre: "</"
                                            }

                                            // 3. Eje: <description>According to the web server&apos;s
                                            else if (lineas[numLinea].Contains(ITEM_DESCRIPTION_TAG))
                                            {
                                                des = Regex.Split(lineas[numLinea], ITEM_DESCRIPTION_TAG)[1];
                                                descripcion = descripcion + des;
                                            }

                                            // 4. Eje: - HP SMH (XSRF)
                                            else
                                                descripcion = descripcion + " " + lineas[numLinea];

                                            numLinea++;
                                        }
                                    }

                                    numLinea++;
                                }

                                // Agregar los datos al objeto tipo vulnerabilidad. 
                                vulnerabilidad.Description = descripcion;
                                vulnerabilidad.Port = puerto;
                                vulnerabilidad.Protocol = protocolo;
                                vulnerabilidad.Severity = severidad;
                                vulnerabilidad.Bid = bid;
                                vulnerabilidad.Cve = cve;
                                vulnerabilidad.ExploitAvailable = Convert.ToBoolean(exploitAvailable);
                                vulnerabilidad.CvssTemporalScore = cvssTemporalScore;
                                vulnerabilidad.RiskFactor = riskFactor;
                                vulnerabilidad.PluginName = pluginName;
                                vulnerabilidad.Sinopsis = sinopsis;
                                vulnerabilidad.Solution = solucion;
                                vulnerabilidad.SeeAlso = seeAlso;
                                vulnerabilidad.Xref = xref;

                                // Agregar la vulnerabilidad a la lista de vulnerabilidades del host.
                                host.Vulnerabilities.Add(vulnerabilidad);

                            }
                        }
                        numLinea++;
                    }
                }

                numLinea++;
            }

            return reporte;
        }

        /// <summary>
        /// Writes a csv where each row represent a vulnerability using the AuxReport given.
        /// Returns a string with the generated file path. 
        /// </summary>
        /// <param name="Report"></param>
        private string WriteCsvFile(AuxReport Report)
        {

            // El número total de filas que debe tener el archivo de salida.
            int tamaño = 1;   // El encabezado
            int indice = 1;
            foreach (AuxHost host in Report.Hosts)
            {
                tamaño += host.Vulnerabilities.Count;
            }

            string[] lineas = new string[tamaño];

            // Escribe el encabezado
            StringBuilder fila = new StringBuilder();
            // Sinopsis
            //if (checkBoxSinopsis.Checked)
            {
                fila.Append(ENCABEZADO_SINOPSIS);
                fila.Append(SEPARADOR);
            }

            // Descripción
            //if (checkBoxDescripcion.Checked)
            {
                fila.Append(ENCABEZADO_DESCRIPCION);
                fila.Append(SEPARADOR);
            }

            // Solución
            //if (checkBoxSolucion.Checked)
            {
                fila.Append(ENCABEZADO_SOLUCION);
                fila.Append(SEPARADOR);
            }

            // IP
            //if (checkBoxIP.Checked)
            {
                fila.Append(ENCABEZADO_IP);
                fila.Append(SEPARADOR);
            }

            // Puerto
            //if (checkBoxPuerto.Checked)
            {
                fila.Append(ENCABEZADO_PUERTO);
                fila.Append(SEPARADOR);
            }

            // Net-bios name
            //if (checkBoxNetBios.Checked)
            {
                fila.Append(ENCABEZADO_NET_BIOS_NAME);
                fila.Append(SEPARADOR);
            }

            // Protocolo
            //if (checkBoxProtocolo.Checked)
            {
                fila.Append(ENCABEZADO_PROTOCOLO);
                fila.Append(SEPARADOR);
            }

            // Risk factor (severidad)
            //if (checkBoxSeveridad.Checked)
            {
                fila.Append(ENCABEZADO_SEVERIDAD);
                fila.Append(SEPARADOR);
            }

            // Explotable
            //if (checkBoxExploit.Checked)
            {
                fila.Append(ENCABEZADO_EXPLOIT_AVAILABLE);
                fila.Append(SEPARADOR);
            }

            // cve
            //if (checkBoxCve.Checked)
            {
                fila.Append(ENCABEZADO_CVE);
                fila.Append(SEPARADOR);
            }

            // BID
            //if (checkBoxBid.Checked)
            {
                fila.Append(ENCABEZADO_BID);
                fila.Append(SEPARADOR);
            }

            // cvss score 
            //if (checkBoxCvss.Checked)
            {
                fila.Append(ENCABEZADO_CVSS_SCORE);
                fila.Append(SEPARADOR);
            }

            // Plug-in name
            //if (checkBoxPlugin.Checked)
            {
                fila.Append(ENCABEZADO_PLUG_IN_NAME);
                fila.Append(SEPARADOR);
            }

            // See Also
            //if (checkBoxInfoAdicional.Checked)
            {
                fila.Append(ENCABEZADO_SEE_ALSO);
                fila.Append(SEPARADOR);
            }

            // Xref
            //if (checkBoxXref.Checked)
            {
                fila.Append(ENCABEZADO_XREF);
                fila.Append(SEPARADOR);
            }

            // Dirección mac
            //if (checkBoxMac.Checked)
            {
                fila.Append(ENCABEZADO_MAC);
                fila.Append(SEPARADOR);
            }

            // Sistema Operativo
            //if (checkBoxOS.Checked)
            {
                fila.Append(ENCABEZADO_SISTEMA_OPERATIVO);
                fila.Append(SEPARADOR);
            }

            lineas[0] = fila.ToString();

            // Recorrer todas las vulnerabilidades del reporte.
            foreach (AuxHost host in Report.Hosts)
            {
                foreach (Vulnerability vulnerabilidad in host.Vulnerabilities)
                {
                    fila = new StringBuilder();
                    string temp = "";

                    // Sinopsis
                    //if (checkBoxSinopsis.Checked)
                    {
                        temp = vulnerabilidad.Sinopsis.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el caracter separador.
                        fila.Append(temp.TrimStart('-'));
                        fila.Append(SEPARADOR);
                    }

                    // Descripción
                    //if (checkBoxDescripcion.Checked)
                    {
                        temp = vulnerabilidad.Description.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el caracter separador.
                        fila.Append(temp.TrimStart('-'));
                        fila.Append(SEPARADOR);
                    }

                    // Solución
                    //if (checkBoxSolucion.Checked)
                    {
                        temp = vulnerabilidad.Solution.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el caracter separador.
                        fila.Append(temp.TrimStart('-'));
                        fila.Append(SEPARADOR);
                    }

                    // ip
                    //if (checkBoxIP.Checked)
                    {
                        temp = host.Host.HostIp.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el caracter separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // puerto
                    //if (checkBoxPuerto.Checked)
                    {
                        temp = vulnerabilidad.Port.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Nombre de bios
                    //if (checkBoxNetBios.Checked)
                    {
                        temp = host.Host.NetBiosName.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Protocolo
                    //if (checkBoxProtocolo.Checked)
                    {
                        temp = vulnerabilidad.Protocol.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Severidad (en palabras)
                    //if (checkBoxSeveridad.Checked)
                    {
                        temp = vulnerabilidad.RiskFactor.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // ¿Existe exploit?
                    //if (checkBoxExploit.Checked)
                    {
                        temp = vulnerabilidad.ExploitAvailable.ToString();
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // cve 
                    //if (checkBoxCve.Checked)
                    {
                        temp = vulnerabilidad.Cve.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // bid
                    //if (checkBoxBid.Checked)
                    {
                        temp = vulnerabilidad.Bid.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Puntaje cvss
                    //if (checkBoxCvss.Checked)
                    {
                        temp = vulnerabilidad.CvssTemporalScore.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Nombre plug in
                    //if (checkBoxPlugin.Checked)
                    {
                        temp = vulnerabilidad.PluginName.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // See also
                    //if (checkBoxInfoAdicional.Checked)
                    {
                        temp = vulnerabilidad.SeeAlso.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Xref
                    //if (checkBoxXref.Checked)
                    {
                        temp = vulnerabilidad.Xref.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // mac
                    //if (checkBoxMac.Checked)
                    {
                        temp = host.Host.Mac.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    // Sistema operativo
                    //if (checkBoxOS.Checked)
                    {
                        temp = host.Host.OperativeSystem.Replace(SEPARADOR, '.');  // Limpia el campo para que no tenga el carater separador.
                        fila.Append(temp);
                        fila.Append(SEPARADOR);
                    }

                    lineas[indice] = fila.ToString();
                    indice++;
                }
            }

            string nombre = Report.Report.Name;
            string path = Path.Combine(Server.MapPath(OUT_DIR), nombre + ".cvs");
            System.IO.File.WriteAllLines(path, lineas);
            return path;
        }
        //-----------------------------------------------------------------------------------
        // Auxiliary classes
        //-----------------------------------------------------------------------------------

        private class AuxReport
        {
            //---------------------------------
            // Properties
            //---------------------------------
            public Report Report { get; set; }

            public List<AuxHost> Hosts { get; set; }


            //---------------------------------
            // Builder
            //---------------------------------

            public AuxReport()
            {
                Hosts = new List<AuxHost>();
                Report = new Report();
            }
        }

        private class AuxHost
        {
            //---------------------------------
            // Properties
            //---------------------------------
            public Host Host { get; set; }
            public List<Vulnerability> Vulnerabilities { get; set; }


            //---------------------------------
            // Builder
            //---------------------------------
            public AuxHost()
            {
                Vulnerabilities = new List<Vulnerability>();
                Host = new Host();
            }
        }
    }
}