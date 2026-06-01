# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100033");
  script_version("2026-05-21T06:54:30+0000");
  script_tag(name:"last_modification", value:"2026-05-21 06:54:30 +0000 (Thu, 21 May 2026)");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("phpBB Forum Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpBB.");

  script_xref(name:"URL", value:"https://www.phpbb.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/board", "/forum", "/phpbb", "/phpBB", "/phpBB2", "/phpBB3",
                               "/phpBB31", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";

  res = http_get_cache( port:port, item:url );

  if( res =~ "^HTTP/1\.[01] 200" && ( egrep( pattern:"^Set-Cookie: phpbb.*", string:res ) ||
      egrep( pattern:".*Powered.*by.*<[^>]+>phpBB</a>.*", string:res ) ||
      egrep( pattern:".*The phpBB Group.*: [0-9]{4}", string:res ) ) ) {

    if( dir == "" )
      rootInstalled = TRUE;

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    url = dir + "/docs/INSTALL.html";

    req = http_get( port:port, item:url );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( res ) {
      vers = eregmatch( string:res, pattern:"phpBB-[a-zA-Z0-9.\-]+_to_([a-zA-Z0-9.\-]+).patch" );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      } else {
        vers = eregmatch( string:res, pattern:"phpBB-([a-zA-Z0-9.\-]+)-patch.zip/tar.bz2" );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    #/docs/INSTALL.html in 3.1.x+ is currently not reliable (3.2.4 has e.g. 3.2.1)
    if( ! version_is_less_equal( version:version, test_version:"3.1.0" ) ) {

      # Overwriting the not reliable version from the INSTALL.html above
      version = "unknown";

      url = dir + "/docs/CHANGELOG.html";

      req = http_get( port:port, item:url );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      # Version is always "Changes since 3.1.x + 1" with some special cases handled below.
      vers = eregmatch( string:res, pattern:"Changes since 3.([1-9]).([0-9]+)(-[a-zA-Z]+[0-9]*)?" );
      if( ! isnull( vers[1] ) && ! isnull( vers[2] ) && ( isnull( vers[3] ) || "-PL" >< vers[3] ) ) {
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        vers[2]++;
        version = "3." + vers[1] + "." + vers[2];

      # There are special cases like "Changes since 3.2.4-RC1" or "Changes since 3.2.0-a1"
      # where the actual version is/was 3.2.4/3.2.0. Unfortnately we don't now if the next version
      # was e.g. RC2 or the final release so we assume the next version as the "final" one.
      } else if( ! isnull( vers[1] ) && ! isnull( vers[2] ) && ! isnull( vers[3] ) ) {
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        version = "3." + vers[1] + "." + vers[2];
      }

      # Another special handling for "Changes since 3.0.x" or "Changes since 3.1.x"
      if( version == "unknown" ) {
        vers = eregmatch( string:res, pattern:"Changes since 3.([0-9]).x" );
        if( ! isnull( vers[1] ) ) {
          conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
          vers[1]++;
          version = "3." + vers[1] + ".0";
        }
      }
    }

    if( version == "unknown" ) {
      foreach style( make_list( "/styles/prosilver/style.cfg", "/styles/subsilver2/style.cfg" ) ) {
        url = dir + style;

        req = http_get( port: port, item:url );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

        vers = eregmatch( string:res, pattern:"version = ([a-zA-Z0-9.\-]+)" );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
          break;
        }
      }
    }

    set_kb_item( name:"www/can_host_tapatalk", value:TRUE ); # nb: Used in sw_tapatalk_detect.nasl for plugin scheduling optimization
    set_kb_item( name:"phpbb/detected", value:TRUE );
    set_kb_item( name:"phpbb/http/detected", value:TRUE );

    cpe = build_cpe( value:tolower( version ), exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:phpbb:phpbb:" );
    if( ! cpe )
      cpe = "cpe:/a:phpbb:phpbb";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"phpBB", version:version, install:install, cpe:cpe,
                                              concludedUrl:conclUrl, concluded:vers[0] ),
                 port:port );
  }
}

exit( 0 );
