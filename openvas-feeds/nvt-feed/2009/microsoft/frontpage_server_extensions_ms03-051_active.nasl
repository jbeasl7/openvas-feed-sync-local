# SPDX-FileCopyrightText: 2009 Christian Eric Edjenguele
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:microsoft:frontpage_server_extensions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101012");
  script_version("2025-07-03T05:42:54+0000");
  script_tag(name:"last_modification", value:"2025-07-03 05:42:54 +0000 (Thu, 03 Jul 2025)");
  script_tag(name:"creation_date", value:"2009-03-16 00:04:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0822", "CVE-2003-0824");

  script_name("Microsoft FrontPage Server Extensions RCE Vulnerability (MS03-051, 813360) - Active Check");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_frontpage_server_extensions_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("microsoft/frontpage_server_extensions/http/detected");

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/security-updates/securitybulletins/2003/ms03-051");

  script_tag(name:"summary", value:"The MS03-051 bulletin addresses two new security vulnerabilities
  in Microsoft FrontPage Server Extensions, the most serious of which could enable an attacker to
  run arbitrary code on a user's system.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP POST requests and checks the
  responses.");

  script_tag(name:"insight", value:"The first vulnerability exists because of a buffer overrun in
  the remote debug functionality of FrontPage Server Extensions.

  This functionality enables users to remotely connect to a server running FrontPage Server
  Extensions and remotely debug content using, for example, Visual Interdev.

  An attacker who successfully exploited this vulnerability could be able to run code with
  IWAM_machinename account privileges on an affected system, or could cause FrontPage Server
  Extensions to fail.

  The second vulnerability is a Denial of Service vulnerability that exists in the SmartHTML
  interpreter.

  This functionality is made up of a variety of dynamic link library files, and exists to support
  certain types of dynamic web content.

  An attacker who successfully exploited this vulnerability could cause a server running Front Page
  Server Extensions to temporarily stop responding to requests.");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct these issues. Please
  see the references for more information.

  Note: This update replaces the security updates contained in the following bulletins: MS01-035 and
  MS02-053.");

  script_tag(name:"solution_type", value:"VendorFix");
  # nb: Response check doesn't look that reliable these days...
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

hostname = http_host_name( port:port );

url = "/_vti_bin/_vti_aut/fp30reg.dll";

req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );

if( ! res || res !~ "^HTTP/1\.[01] 500" )
  exit( 99 );

qry = string( "POST ", url, ' HTTP/1.0\r\n',
              'Connection: Keep-Alive\r\n',
              "Host: ", hostname, '\r\n',
              "Transfer-Encoding:", ' chunked\r\n',
              '1\r\n\r\nX\r\n0\r\n\r\n');
reply = http_keepalive_send_recv( port:port, data:qry, bodyonly:FALSE );

if( egrep( pattern:"Microsoft-IIS/[45]\.[01]", string:reply, icase:TRUE ) ) {

  qry2 = string( "POST ", url, ' HTTP/1.0\r\n',
                 'Connection: Keep-Alive\r\n',
                 "Host: ", hostname, '\r\n',
                 "Transfer-Encoding:", ' chunked\r\n',
                 '0\r\n\r\nX\r\n0\r\n\r\n');
  response = http_keepalive_send_recv( port:port, data:qry2, bodyonly:FALSE );

  if( egrep( pattern:"^HTTP/1\.[01] 200", string:response, icase:TRUE ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
