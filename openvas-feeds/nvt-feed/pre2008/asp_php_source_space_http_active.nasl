# SPDX-FileCopyrightText: 2002 Michel Arboi
# SPDX-FileCopyrightText: New code / detection methods since 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11071");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2001-1248", "CVE-2007-3407");
  script_name("ASP/PHP '%20' Source Code Disclosure Vulnerability - Active Check");
  script_category(ACT_ATTACK); # nb: The '%20' is probably already seen as an attack
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "gb_php_http_detect.nasl", "DDI_Directory_Scanner.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210208165641/http://www.securityfocus.com/bid/2975");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210208165641/http://www.securityfocus.com/bid/24618");

  script_tag(name:"summary", value:"Multiple products are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"It is possible to get the source code of the remote
  ASP/PHP scripts by appending %20 at the end of the request (like GET /default.asp%20).");

  script_tag(name:"impact", value:"ASP/PHP source code could usually contain sensitive
  information.");

  script_tag(name:"affected", value:"The following products are known to be affected:

  - vWebServer 1.2

  - SHTTPD 1.38

  Other products / versions might be affected as well.");

  script_tag(name:"solution", value:"Install all the latest security patches for the affected
  product or contact the vendor for a solution.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

function check_php_or_asp( file, port, check_php, check_asp ) {

  local_var file, port, check_php, check_asp;
  local_var url, req, res, report;

  url = string( file, "%20" );
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res || ! ereg( pattern:"^HTTP/1\.[01] 200", string:res ) )
    return FALSE;

  if( check_asp ) {

    if( egrep( string:res, pattern:"^[Cc]ontent-[Tt]ype\s*:\s*application/octet-stream", icase:FALSE ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      return TRUE;
    }

    if( egrep( string:res, pattern:"^\s*<%", icase:FALSE ) &&
        "%>" >< res ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      return TRUE;
    }

  } else if( check_php ) {

    if( egrep( string:res, pattern:"^\s*<\?php", icase:FALSE ) &&
        "?>" >< res ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      return TRUE;
    }
  }

  return FALSE;
}

function check_php( port, host ) {

  local_var port, host;
  local_var files;

  if( check_php_or_asp( file:"/index.php", port:port, check_asp:FALSE, check_php:TRUE ) )
    return;

  if( ! files = http_get_kb_file_extensions( port:port, host:host, ext:"php" ) )
    return;

  files = make_list( files );
  check_php_or_asp( file:files[0], port:port, check_asp:FALSE, check_php:TRUE );
  return;
}

function check_asp( port, host ) {

  local_var port, host;
  local_var files;

  if( check_php_or_asp( file:"/default.asp", port:port, check_asp:TRUE, check_php:FALSE ) )
    return;

  if( ! files = http_get_kb_file_extensions( port:port, host:host, ext:"asp" ) )
    return;

  files = make_list( files );
  check_php_or_asp( file:files[0], port:port, check_asp:TRUE, check_php:FALSE );
  return;
}

port = http_get_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

if( http_can_host_asp( port:port ) )
  check_asp( port:port, host:host );

if( http_can_host_php( port:port ) )
  check_php( port:port, host:host );

exit( 0 );
