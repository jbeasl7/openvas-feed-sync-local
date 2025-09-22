# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800587");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DokuWiki Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of DokuWiki.

  The script sends a connection request to the server and attempts to extract the
  version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/wiki", "/dokuwiki", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/feed.php", port:port );
  rcv = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  req = http_get( item:dir + "/doku.php", port:port );
  rcv2 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( ( 'generator="FeedCreator' >!< rcv && 'DokuWiki"' >!< rcv )
        && "Set-Cookie: DokuWiki=" >!< rcv
        && "<error>RSS feed is disabled.</error>" >!< rcv
        && "Driven by DokuWiki" >!< rcv2
        && 'generator" content="DokuWiki' >!< rcv2 )
    continue;

  if( dir == "" ) rootInstalled = TRUE;

  set_kb_item( name:"dokuwiki/installed", value:TRUE );

  version = "unknown";

  # nb: Check if the install is missing a patch. The output of this notify
  # area is currently available at http://update.dokuwiki.org/check/
  if( "://www.dokuwiki.org/update_check" >< rcv2 &&
      ( '<div class="notify">' >< rcv2 || '<div class="msg notify">' >< rcv2 ) ) {
    set_kb_item( name:"dokuwiki/missing_updates/" + port + install, value:TRUE );
    set_kb_item( name:"dokuwiki/missing_updates", value:TRUE );
  }

  # nb: The generator included the version up to release 2009-12-25
  vers = eregmatch( pattern:"DokuWiki Release (rc([0-9\-])?)?([0-9]{4}\-[0-9]{2}\-[0-9]{2}[a-z]?)", string:rcv2 );
  if( ! vers[3] ) {
    # nb: The VERSION file is sometimes unprotected.
    url = dir + "/VERSION";
    req = http_get( item:url, port:port );
    rcv2 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    vers = eregmatch( pattern:"(rc([0-9\-])?)?([0-9]{4}\-[0-9]{2}\-[0-9]{2}[a-z]?)", string:rcv2 );
    if( ! isnull( vers[3] ) ) {
      version = vers[3];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  } else {
    version = vers[3];
  }

  cpe = build_cpe( value:version, exp:"^([0-9\-]+[a-z]?)", base:"cpe:/a:dokuwiki:dokuwiki:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:dokuwiki:dokuwiki';

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"DokuWiki",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
