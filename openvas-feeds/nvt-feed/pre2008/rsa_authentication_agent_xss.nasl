# SPDX-FileCopyrightText: 2005 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

#  ref : Oliver Karow <oliver.karow@gmx.de>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18213");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1118");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13168");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("RSA Security RSA Authentication Agent For Web XSS");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgraded to version 5.3 or newer.");

  script_tag(name:"summary", value:"The remote host seems to be running the RSA Security RSA Authentication
  Agent for web.

  The remote version of this software is contains an input validation
  flaw in the 'postdata' variable. An attacker may use it to perform a
  cross site scripting attack.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = '/WebID/IISWebAgentIF.dll?postdata="><script>foo</script>';
req = http_get( item:url, port:port);
res = http_keepalive_send_recv( port:port, data:req );
if( ! res ) exit( 0 );

if( res =~ "^HTTP/1\.[01] 200" && "<TITLE>RSA SecurID " >< res && ereg( pattern:"<script>foo</script>", string:res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
}

exit( 0 );
