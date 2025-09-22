# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17230");
  script_version("2025-04-11T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-04-11 05:40:28 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CERN httpd Access Control Bypass Vulnerability - Active Check");
  script_category(ACT_ATTACK); # nb: Requests might be already seen as an attack
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Web Servers");
  script_dependencies("find_service.nasl", "no404.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("www/content/auth_required");

  script_xref(name:"URL", value:"https://insecure.org/sploits/CERN.httpd.slashbug.html");
  script_xref(name:"URL", value:"https://seclists.org/bugtraq/1997/Apr/162");

  script_tag(name:"summary", value:"CERN httpd is prone to an access control bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"It is possible to access protected web pages
  by replacing '/' with e.g. '//' or '/./'.

  This was a bug in old versions of CERN httpd web server.");

  script_tag(name:"solution", value:"Update your web server or tighten your filtering rules.

  A workaround consisted in rejecting patterns like:

  //*

  *//*

  /./*

  */./*");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("http_func.inc");
include("http_404.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

function check( port, url ) {

  local_var port, url;
  local_var no404, req, res;

  res = http_get_cache( item:url, port:port );
  if( ! res )
    return;

  # nb:
  # - To prevent a false positive on Nextcloud / ownCloud systems on "/remote.php/dav" because these
  #   are always showing the login page (with a 200) on such "unknown" URLs
  # - On further false positives additional such exclusions could be added here

  # e.g.:
  #
  #   <title>
  #     Nextcloud   </title>
  #
  # or:
  #
  # <title>ownCloud</title>
  #
  # or:
  #
  #             Nextcloud         </h1>
  #
  # or:
  #
  # <a href="https://nextcloud.com" target="_blank" rel="noreferrer noopener" class="entity-name">Nextcloud</a> - a safe home for all your data     </p>
  # <a href="https://<redacted>" target="_blank" rel="noreferrer noopener" class="entity-name">MyCompany</a> - a safe home for all your data      </p>
  #
  # nb:
  # - the UTF-8 dash before "a safe home" has been replaced
  # - there are tabs instead of spaces used but these have been replaced in the examples as well
  #
  if( "/remote.php" >< url && egrep( string:res, pattern:"(a safe home for all your data\s*</p>|(Nextcloud|ownCloud)\s*</(title|h1)>)", icase:FALSE ) )
    return;

  if( res =~ "^HTTP/[0-9]\.[0-9] +40[13]" ) {
    return 403;
  } else if( res =~ "^HTTP/[0-9]\.[0-9] +200 " ) {
    if( no404 && no404 >< res )
      return 404;
    else
      return 200;
  } else {
    return;
  }
}

port  = http_get_port( default:80 );
host  = http_host_name( dont_add_port:TRUE );
no404 = http_get_no404_string( port:port, host:host );

if( ! dirs = http_get_kb_auth_required( port:port, host:host ) )
  exit( 0 );

foreach dir( dirs ) {

  if( check( port:port, url:dir, no404:no404 ) == 403 ) {
    foreach pat( make_list( "//", "/./" ) ) {
      dir2 = ereg_replace( pattern:"^/", replace:pat, string:dir );
      if( check( port:port, url:dir2, no404:no404 ) == 200 ) {
        report = http_report_vuln_url( port:port, url:dir2 );
        security_message( port:port, data:report );
        exit( 0 );
      }

      dir2 = ereg_replace( pattern: "^(.+)/", replace:"\\1" + pat, string:dir );
      if( check( port:port, url:dir2 ) == 200) {
        report = http_report_vuln_url( port:port, url:dir2 );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
