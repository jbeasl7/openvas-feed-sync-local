# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Ref: Dr_insane

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14681");
  script_version("2023-11-14T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-11-14 05:06:15 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11111");
  script_xref(name:"OSVDB", value:"9514");
  script_xref(name:"OSVDB", value:"9515");
  script_xref(name:"OSVDB", value:"9516");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Keene digital media server XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "cross_site_scripting.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"summary", value:"The remote host runs Keene digital media server, a webserver
  used to share digital information.

  This version is vulnerable to multiple cross-site scripting attacks which
  may allow an attacker to steal the cookies of users of this site.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

urls = make_list(
"/dms/slideshow.kspx?source=<script>foo</script>",
"/dms/dlasx.kspx?shidx=<script>foo</script>",
"/igen/?pg=dlasx.kspx&shidx=<script>foo</script>",
"/dms/mediashowplay.kspx?pic=<script>foo</script>&idx=0",
"/dms/mediashowplay.kspx?pic=0&idx=<script>foo</script>"
 );

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach url( urls ) {

  buf = http_get( item:url, port:port );
  r = http_keepalive_send_recv( port:port, data:buf, bodyonly:FALSE );
  if(!r) exit( 0 );

  if( r =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< r ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
