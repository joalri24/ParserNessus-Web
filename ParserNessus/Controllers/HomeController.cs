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

        

    }
}
