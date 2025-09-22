# SPDX-FileCopyrightText: 2000 SecuriTeam
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10403");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1178");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2000-0381");
  script_name("DBMan CGI server information leakage");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2000 SecuriTeam");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version");

  script_tag(name:"summary", value:"It is possible to cause the DBMan
  CGI to reveal sensitive information, by requesting a URL such as:

  GET /scripts/dbman/db.cgi?db=no-db");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

req = http_get( item:"/scripts/dbman/db.cgi?db=no-db", port:port );
result = http_send_recv( port:port, data:req );
backup = result;
report = string( "\nIt is possible to cause the DBMan\nCGI to reveal sensitive information, by requesting a URL such as:\n\n",
"GET /scripts/dbman/db.cgi?db=no-db\n\nthe following could be obtained: \n\n");

if( "CGI ERROR" >< result ) {
  result = strstr(backup, string("name: no-db at "));
  result = result - strstr(result, string(" line "));
  result = result - "name: no-db at ";
  report = "CGI full path is at: " + result + string("\n");

  result = strstr(backup, string("Perl Version        : "));
  result = result - strstr(result, string("\n"));
  result = result - string("Perl Version        : ");
  report = report + "Perl version: " + result + string("\n");

  result = strstr(backup, string("PATH                : "));
  result = result - strstr(result, string("\n"));
  result = result - string("PATH                : ");
  report = report + "Server path: " + result + string("\n");

  result = strstr(backup, string("SERVER_ADDR         : "));
  result = result - strstr(result, string("\n"));
  result = result - string("SERVER_ADDR         : ");
  report = report + "Server real IP: " + result + string("\n");

  result = strstr(backup, string("SERVER_SOFTWARE     : "));
  result = result - strstr(result, string("\n"));
  result = result - string("SERVER_SOFTWARE     : ");
  report = report + "Server software: " + result + string("\n");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
