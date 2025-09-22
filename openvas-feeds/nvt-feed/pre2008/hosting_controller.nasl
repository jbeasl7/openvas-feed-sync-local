# SPDX-FileCopyrightText: 2003 John Lampe
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11745");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0466");
  script_name("Hosting Controller vulnerable ASP pages");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 John Lampe");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2002-01/0039.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3808");

  script_tag(name:"solution", value:"Remove or update the software.");

  script_tag(name:"summary", value:"The Hosting Controller application resides on this server.
  This version is vulnerable to multiple remote exploits.");

  script_tag(name:"impact", value:"At attacker may make use of this vulnerability and use it to
  gain access to confidential data and/or escalate their privileges on the Web server.");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if( ! http_can_host_asp(port:port) )
  exit(0);

files = make_list( "/statsbrowse.asp", "/servubrowse.asp", "/browsedisk.asp", "/browsewebalizerexe.asp", "/sqlbrowse.asp" );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( files ) {
    if(http_is_cgi_installed_ka(item:string(dir, file), port:port)) {
      url = dir + file + "?filepath=c:" + raw_string(0x5C,0x26) + "Opt=3";
      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if(!res)
        continue;

      if( (egrep(pattern:".*\.BAT.*", string:res)) || (egrep(pattern:".*\.ini.*", string:res)) ) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
