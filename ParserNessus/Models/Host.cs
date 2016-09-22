using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ParserNessus.Models
{
    public class Host
    {
        public string HostName { get; set; }
        public string HostEnd { get; set; }
        public string HostStart { get; set; }
        public string HostIp { get; set; }
        public string OperativeSystem { get; set; }
        public string Mac { get; set; }
        public string NetBiosName { get; set; }

        // Foreign key
        public int ReportId { get; set; }
        public Report Report { get; set; }

    }
}