using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        public ActionResult Upload(HttpPostedFileBase file)
        {

            ViewBag.Lines = new string[] { "nada", "más nada" };
            if (file.ContentLength > 0)
            {
                var fileName = Path.GetFileName(file.FileName);
                var path = Path.Combine(Server.MapPath("~/App_Data/uploads"), fileName);
                file.SaveAs(path);

                // TODO Leer el archivo

                string[] lines = System.IO.File.ReadAllLines(path);
                ViewBag.Lines = lines;


                return RedirectToAction("Download", new { FileName = path });
            }


            return View("File");

        }

        // GET Upload/Download?filename=name
        /// <summary>
        /// Return a file to the user. Displays the download option.
        /// </summary>
        /// <param name="FileName"></param>
        /// <returns></returns>
        public FileResult Download(string FileName)
        {
            byte[] fileBytes = System.IO.File.ReadAllBytes(FileName);
            string fileName = "myfile.cvs"; // TODO creo que el nombre lo debe obtener de otro lado.
            return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
        }


        //-----------------------------------------------------------------------------------
        // Methods
        //-----------------------------------------------------------------------------------

        /// <summary>
        /// Parses the nessus file. if it success redirects to the Download action.
        /// </summary>
        /// <param name="filePath"></param>
        private void ReadFile(string filePath)
        {
            //TODO
        }
    }
}