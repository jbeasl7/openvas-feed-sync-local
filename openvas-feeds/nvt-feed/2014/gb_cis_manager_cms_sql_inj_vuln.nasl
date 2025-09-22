# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804558");
  script_version("2024-06-13T05:05:46+0000");
  script_cve_id("CVE-2014-2847");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-04-28 19:58:39 +0530 (Mon, 28 Apr 2014)");
  script_name("CIS Manager 'TroncoID' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32660");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66590");
  script_xref(name:"URL", value:"http://www.cnnvd.org.cn/vulnerability/show/cv_id/2014040155");

  script_tag(name:"summary", value:"CIS Manager is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able
  execute sql query or not.");

  script_tag(name:"insight", value:"Input passed via the 'TroncoID' GET parameter to default.asp is not
  properly sanitised before being used in a sql query.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  script code and manipulate SQL queries in the backend database allowing
  for the manipulation or disclosure of arbitrary data.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

http_port = http_get_port( default:80 );
if( ! http_can_host_asp( port:http_port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/cis", "/cms", "/cismanager", "/cismanagercms", http_cgi_dirs( port:http_port ) ) ) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item:dir + "/default.asp",  port:http_port );

  if( ">CIS Manager<" >< rcvRes && ">Construtiva" >< rcvRes ) {

    url = dir + "/default.asp?TroncoID='SQLInjTest";

    if( http_vuln_check( port:http_port, url:url, check_header:TRUE, pattern:"'SQLInjTest'", extra_check:">error '80040e14'<" ) ) {
      report = http_report_vuln_url( port:http_port, url:url );
      security_message( port:http_port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
