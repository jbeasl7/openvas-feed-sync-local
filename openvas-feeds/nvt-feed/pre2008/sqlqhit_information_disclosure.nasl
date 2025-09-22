# SPDX-FileCopyrightText: 2001 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10765");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2001-0986");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SQLQHit Directory Structure Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2001 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securiteam.com/tools/5QP0N1F55Q.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3339");
  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5HP05150AQ.html");
  script_xref(name:"URL", value:"http://www.securiteam.com/windowsntfocus/5RP0D1F4AU.html");

  script_tag(name:"solution", value:"Use Microsoft's Secure IIS Guide (For IIS 4.0 or IIS 5.0 respectively) or
  Microsoft's IIS Lockdown tool to remove IIS samples.");

  script_tag(name:"summary", value:"The Sample SQL Query CGI is present.");

  script_tag(name:"impact", value:"The sample allows anyone to structure a certain query that would retrieve
  the content of directories present on the local server.");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))
  exit(0);

files = make_list( "/sqlqhit.asp", "/SQLQHit.asp" );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( files ) {
    url = string(dir, file, "?CiColumns=*&CiScope=webinfo");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if(!buf)
      continue;

    if (("VPATH" >< buf) && ("PATH" >< buf) && ("CHARACTERIZATION" >< buf)) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

exit(99);
