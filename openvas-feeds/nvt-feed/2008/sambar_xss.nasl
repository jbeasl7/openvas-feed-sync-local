# SPDX-FileCopyrightText: 2008 Renaud Deraison
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sambar:sambar_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80083");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2003-1284", "CVE-2003-1285");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Sambar XSS Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2008 Renaud Deraison");
  script_family("Web application abuses");
  script_dependencies("gb_sambar_server_http_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sambar_server/http/detected");

  script_tag(name:"summary", value:"The Sambar web server comes with a set of CGIs that are prone
  to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple HTTP GET requests and checks the responses.");

  script_tag(name:"impact", value:"An attacker may use this flaw to steal the cookies of your web
  users.");

  script_tag(name:"solution", value:"Delete the affected CGIs.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/7209");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) )
  exit( 0 );

cgis = make_list(
  "/netutils/ipdata.stm?ipaddr=",
  "/netutils/whodata.stm?sitename=",
  "/netutils/finddata.stm?user=",
  "/isapi/testisa.dll?check1=",
  "/cgi-bin/environ.pl?param1=",
  "/samples/search.dll?logic=AND&query=",
  "/wwwping/index.stm?wwwsite=",
  "/syshelp/stmex.stm?bar=456&foo=",
  "/syshelp/cscript/showfunc.stm?func=",
  "/syshelp/cscript/showfncs.stm?pkg=",
  "/syshelp/cscript/showfnc.stm?pkg=",
  "/sysuser/docmgr/ieedit.stm?path=",
  "/sysuser/docmgr/edit.stm?path=",
  "/sysuser/docmgr/iecreate.stm?path=",
  "/sysuser/docmgr/create.stm?path=",
  "/sysuser/docmgr/info.stm?path=",
  "/sysuser/docmgr/ftp.stm?path=",
  "/sysuser/docmgr/htaccess.stm?path=",
  "/sysuser/docmgr/mkdir.stm?path=",
  "/sysuser/docmgr/rename.stm?path=",
  "/sysuser/docmgr/search.stm?path=",
  "/sysuser/docmgr/sendmail.stm?path=",
  "/sysuser/docmgr/template.stm?path=",
  "/sysuser/docmgr/update.stm?path=",
  "/sysuser/docmgr/vccheckin.stm?path=",
  "/sysuser/docmgr/vccreate.stm?path=",
  "/sysuser/docmgr/vchist.stm?path=",
  "/cgi-bin/testcgi.exe?" );

tmpReport = NULL;

foreach cgi( cgis ) {

  url = cgi + "<script>foo</script>";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( isnull( res ) )
    continue;

  if( res =~ "^HTTP/1\.[01] 200" && "<script>foo</script>" >< res ) {
    tmpReport += http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
  }
}

if( ! isnull( tmpReport ) ) {
  report = "The following Sambar default CGIs are vulnerable to a cross-site scripting attack:";
  report += '\n\n' + tmpReport;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
