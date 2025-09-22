# SPDX-FileCopyrightText: 2004 by DokFLeed
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14312");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11612");
  script_name("ScanMail file check");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2004 by DokFLeed");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script attempts to read sensitive files used by Trend
  ScanMail, an anti-virus protection program for Domino (formerly Lotus Notes).");

  script_tag(name:"impact", value:"An attacker, exploiting this flaw, may gain access to confidential
  data or disable the anti-virus protection.");

  script_tag(name:"solution", value:"Password protect access to these files.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

files = make_array("/smency.nsf"   , "Encyclopedia",
                   "/smconf.nsf"   , "Configuration",
                   "/smhelp.nsf"   , "Help",
                   "/smftypes.nsf" , "File Types",
                   "/smmsg.nsf"    , "Messages",
                   "/smquar.nsf"   , "Quarantine",
                   "/smtime.nsf"   , "Scheduler",
                   "/smsmvlog.nsf" , "Log",
                   "/smadmr5.nsf"  , "Admin Add-in");
report = "";
foreach path(keys(files)) {

  req = http_get(item:path, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if("Trend ScanMail" >< res) {
    if(!report) {
      report = "The following files were found:";
    }
    report += string("\n    ", path, " - ", files[path]);
  }
}

if(report) {
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
