# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10960");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-0892");
  script_name("ServletExec 4.1 ISAPI Physical Path Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Use the main ServletExec Admin UI to set a global error page for the entire
  ServletExec Virtual Server.");

  script_tag(name:"summary", value:"By requesting a non-existent .JSP file, or by invoking the JSPServlet
  directly and supplying no filename, it is possible to make the ServletExec
  ISAPI filter disclose the physical path of the webroot.");

  script_xref(name:"URL", value:"http://www.westpoint.ltd.uk/advisories/wp-02-0006.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4793");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

url = "/servlet/com.newatlanta.servletexec.JSP10Servlet";
req = http_get(item:url, port:port);
r = http_keepalive_send_recv(port:port, data:req);

if ("newatlanta" >< r && "Error. The file was not found. (filename = " ><r ) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
