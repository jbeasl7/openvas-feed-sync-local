# SPDX-FileCopyrightText: 2002 Matt Moore
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10836");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/3702");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1199");
  script_name("Agora CGI Cross Site Scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Agora 4.0e or newer.");
  script_tag(name:"summary", value:"The remote web server contains a CGI which is vulnerable to a cross-site
  scripting issue.

  Description :

  Agora is a CGI based e-commerce package. Due to poor input validation,
  Agora allows an attacker to execute cross-site scripting attacks.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

url = "/store/agora.cgi?cart_id=<SCRIPT>alert(document.domain)</SCRIPT>&xm=on&product=HTML";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( isnull( res ) ) exit( 0 );

if( res =~ "^HTTP/1\.[01] 200" && "<SCRIPT>alert(document.domain)</SCRIPT>" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
