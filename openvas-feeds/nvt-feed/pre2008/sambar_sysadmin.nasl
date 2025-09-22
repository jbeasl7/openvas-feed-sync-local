# SPDX-FileCopyrightText: 2000 Hendrik Scholz
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10416");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Sambar /sysadmin Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("gb_sambar_server_http_detect.nasl");
  script_require_ports("Services/www", 3135);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"summary", value:"The Sambar webserver a web interface for configuration purposes.

  The admin user has no password and there are some other default users without passwords. Everyone
  could set the HTTP-Root to c:\ and delete existing files.");

  script_tag(name:"solution", value:"Change the passwords via the webinterface.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2255");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/sysadmin/dbms/dbms.htm";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( egrep( pattern:"[sS]ambar", string:res ) ) {
  if( ereg( pattern:"^HTTP/1\.[01] 403", string:res ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report);
    exit( 0 );
  }
}

exit( 99 );
