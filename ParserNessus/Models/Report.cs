using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ParserNessus.Models
{
    public class Report
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public DateTime Date { get; set; }
        public string Comments { get; set; }
    }
}