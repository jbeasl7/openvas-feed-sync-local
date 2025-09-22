# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103669");
  script_version("2024-06-28T15:38:46+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("CometChat RCE and XSS Vulnerabilities");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2013-02-26 12:54:40 +0100 (Tue, 26 Feb 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57979");

  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
  for more information.");

  script_tag(name:"summary", value:"CometChat is prone to a cross-site scripting (XSS) vulnerability and a
  remote code execution (RCE) vulnerability because the application fails to sufficiently sanitize
  user-supplied data.");

  script_tag(name:"impact", value:"An attacker may leverage the cross-site scripting issue to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and launch other attacks.

  An attacker can exploit the remote code-execution issue to execute arbitrary code in the context of the
  application. Failed attacks may cause denial-of-service conditions.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/cometchat", "/chat", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/index.html';
  buf = http_get_cache( item:url, port:port );

  if( "<title>CometChat" >< buf ) {
    url = dir + '/modules/chatrooms/chatrooms.php?action=phpinfo';
    if( http_vuln_check( port:port, url:url, pattern:"<title>phpinfo\(\)" ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
