# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804455");
  script_version("2024-06-13T05:05:46+0000");
  script_cve_id("CVE-2014-3749");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2014-05-26 16:44:36 +0530 (Mon, 26 May 2014)");
  script_name("CIS Manager 'email' Parameter SQL Injection Vulnerability");

  script_tag(name:"summary", value:"CIS Manager is prone to an SQL injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
  SQL injection error.");

  script_tag(name:"insight", value:"The flaw is due to the /autenticar/lembrarlogin.asp script not properly
  sanitizing user-supplied input to the 'email' parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to inject or manipulate SQL
  queries in the back-end database, allowing for the manipulation or disclosure
  of arbitrary data.");

  script_tag(name:"affected", value:"CIS Manager CMS");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93252");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67442");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/May/73");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

http_port = http_get_port(default:80);
if( ! http_can_host_asp( port:http_port ) ) exit( 0 );

foreach dir (make_list_unique("/", "/autenticar", "/cismanager", "/site", "/construtiva", http_cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/login.asp"), port:http_port);

  if(rcvRes && rcvRes  =~ ">Construtiva .*Internet Software" ||
     "http://www.construtiva.com.br/" >< rcvRes)
  {
    if(http_vuln_check(port:http_port, url: dir + "/lembrarlogin.asp?email='",
       pattern:"SQL Server.*>error.*'80040e14'"))
    {

      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
