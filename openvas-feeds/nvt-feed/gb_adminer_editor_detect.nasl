# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108536");
  script_version("2025-08-28T05:39:05+0000");
  script_tag(name:"last_modification", value:"2025-08-28 05:39:05 +0000 (Thu, 28 Aug 2025)");
  script_tag(name:"creation_date", value:"2019-01-21 07:51:41 +0100 (Mon, 21 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adminer Editor Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.adminer.org/en/editor/");

  script_tag(name:"summary", value:"The script sends a HTTP request to the remote
  server and tries to identify an Adminer Editor installation and it's version from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/adminer", "/editor", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  if( rootInstalled )
    break;

  url  = dir + "/editor.php";
  buf  = http_get_cache( item:url, port:port );

  url2 = dir + "/";
  buf2 = http_get_cache( item:url2, port:port );

  # nb: Source-Code / Detection-Pattern are nearly the same as in gb_adminer_http_detect.nasl
  if( ( buf =~ "^HTTP/1\.[01] 200" || buf2 =~ "^HTTP/1\.[01] 200" ) &&
      ( "<title>Login - Editor</title>" >< buf ||
        "<title>Login - Editor</title>" >< buf2 ||
        ( "://www.adminer.org/editor/'" >< buf && "id='h1'>Editor</a>" >< buf ) ||
        ( "://www.adminer.org/editor/'" >< buf2 && "id='h1'>Editor</a>" >< buf2 ) ) ) {

    version  = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
    if( install == "/" )
      rootInstalled = TRUE;

    # id='h1'>Editor</a> <span class="version">4.7.0</span>
    #
    # onclick="bodyClick(event);" onload="verifyVersion('4.3.1');">
    # id='h1'>Editor</a> <span class="version">4.3.1</span>

    vers = eregmatch( pattern:"verifyVersion(, '|\(')([^']+)'", string:buf, icase:FALSE );
    if( vers[2] ) {
      version = vers[2];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"verifyVersion(, '|\(')([^']+)'", string:buf2, icase:FALSE );
      if( vers[2] ) {
        version = vers[2];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:'class="version">([^<]+)<', string:buf, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      vers = eregmatch( pattern:'class="version">([^<]+)<', string:buf2, icase:FALSE );
      if( vers[1] ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    set_kb_item( name:"www/" + port + "/adminer_editor", value:version );
    set_kb_item( name:"adminer/editor/detected", value:TRUE );
    register_and_report_cpe( app:"Adminer Editor", ver:version, concluded:vers[0], conclUrl:conclUrl, base:"cpe:/a:adminer:adminer_editor:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www" );
  }
}

exit( 0 );
