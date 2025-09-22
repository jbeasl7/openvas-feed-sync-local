# SPDX-FileCopyrightText: 2005 Josh Zlatin-Amishav
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18290");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13382");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13383");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13384");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13385");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13639");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MetaCart E-Shop ProductsByCategory.ASP SQL and XSS Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Due to a lack of user input validation, the remote version of
  MetaCart e-Shop is vulnerable to various SQL injection vulnerabilities and cross site scripting attacks.");

  script_tag(name:"impact", value:"An attacker may exploit these flaws to execute arbitrary SQL commands against
  the remote database or to perform a cross site scripting attack using the remote host.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_asp(port:port))
  exit(0);

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port )) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/productsByCategory.asp?intCatalogID=3'&strCatalog_NAME=VT-Test";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    continue;

  if("80040e14" >< res && "cat_ID = 3'" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
