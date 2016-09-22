using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace ParserNessus.Controllers
{
    public class HomeController : Controller
    {

        // ------------------------------------------------------------
        // Properties
        // ------------------------------------------------------------

        string Filename = "";
        // ------------------------------------------------------------
        // Actions
        // ------------------------------------------------------------

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult Upload()
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

            ViewBag.Lines = new string[] { "nada", "más nada"};
            if (file.ContentLength > 0)
            {
                var fileName = Path.GetFileName(file.FileName);
                var path = Path.Combine(Server.MapPath("~/App_Data/uploads"), fileName);
                file.SaveAs(path);

                string[] lines = System.IO.File.ReadAllLines(path);
                ViewBag.Lines = lines;
                return RedirectToAction("Download", new { FileName = path });
            }


            return View("File");
            
        }

        public FileResult Download(string FileName)
        {
            byte[] fileBytes = System.IO.File.ReadAllBytes(FileName);
            string fileName = "myfile.ext";
            return File(fileBytes, System.Net.Mime.MediaTypeNames.Application.Octet, fileName);
        }

        // ------------------------------------------------------------
        // Methods
        // ------------------------------------------------------------

    }
}
