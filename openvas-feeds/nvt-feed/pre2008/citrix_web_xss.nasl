# SPDX-FileCopyrightText: 2003 Michael J. Richardson
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12301");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-1157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/8939");
  script_xref(name:"OSVDB", value:"2762");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Citrix Web Interface XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2003 Michael J. Richardson");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "cross_site_scripting.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to Citrix Web Interface 2.1 or newer.");
  script_tag(name:"summary", value:"The remote server is running a Citrix Web Interface server that is vulnerable to cross site scripting.");
  script_tag(name:"impact", value:"When a user fails to authenticate, the Citrix Web Interface includes the error message text in the URL.
  The error message can be tampered with to perform an XSS attack.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

host = http_host_name( dont_add_port:TRUE );
if( http_get_has_generic_xss( port:port, host:host ) ) exit( 0 );

foreach dir( make_list( "/citrix/nfuse/default", "/citrix/MetaframeXP/default" ) ) {

  url = dir + "/login.asp?NFuse_LogoutId=&NFuse_MessageType=Error&NFuse_Message=<SCRIPT>alert('Ritchie')</SCRIPT>&ClientDetection=ON";

  if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<SCRIPT>alert\('Ritchie'\)</SCRIPT>" ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
