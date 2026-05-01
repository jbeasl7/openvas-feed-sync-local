# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100112");
  script_version("2026-04-17T15:51:27+0000");
  script_tag(name:"last_modification", value:"2026-04-17 15:51:27 +0000 (Fri, 17 Apr 2026)");
  script_tag(name:"creation_date", value:"2009-04-08 12:09:59 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Serendipity Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://docs.s9y.org/");
  script_xref(name:"URL", value:"https://github.com/s9y/Serendipity");

  script_tag(name:"summary", value:"HTTP based detection of Serendipity.");

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
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/serendipity", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );
  if( ! buf )
    continue;

  if( buf =~ "^HTTP/1\.[01] 200" && (

      # nb: Both from the same system
      #
      # <meta name="Powered-By" content="Serendipity v.2.3.5" />
      # <div id="serendipity_credit_line">Powered by <a href="http://www.s9y.org">s9y</a>
      #
      # This was on an older 1.6.2 install with Copyright year 2008:
      # <li>Powered by <a href="http://www.s9y.org">Serendipity</a></li>
      egrep( pattern:"Powered.by.*(Serendipity|>s9y</a>)", string:buf, icase:TRUE ) ||

      '<meta name="generator" content="Serendipity' >< buf ) ) {

    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # <meta name="generator" content="Serendipity v.2.6-beta1">
    # <meta name="generator" content="Serendipity v.2.6.0">
    # <meta name="Powered-By" content="Serendipity v.2.3.5" />
    # <meta name="Powered-By" content="Serendipity v.1.6.2" />
    # <meta name="Powered-By" content="Serendipity v.1.3-beta1" />
    # <meta name="Powered-By" content="Serendipity v.1.3.1" />
    # <meta name="Powered-By" content="Serendipity v.1.5.3-2" />
    #
    vers = eregmatch( string:buf, pattern:"Serendipity v\.([0-9.]+[-a-zA-Z0-9]*)", icase:TRUE );
    if( isnull( vers[1] ) ) {

      url = dir + "/serendipity_admin.php";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      # <span>Powered by Serendipity 1.6.2 and PHP 5.3.3</span>
      # <title>Serendipity Administration Suite</title>
      # <h1>Serendipity Administration Suite</h1>
      # <h2>Welcome to the Serendipity Administration Suite.</h2>
      #
      # or:
      #
      # <title> - Serendipity Administration Suite</title>
      # <span>Powered by Serendipity 1.5.3-2 and PHP 5.6.40-0+deb8u12</span>
      # <h1>Serendipity Administration Suite</h1>
      # <h2>Welcome to the Serendipity Administration Suite.</h2>
      #
      # or:
      #
      # <title>$sometitle | Serendipity Administration Suite</title>
      # <p>Powered by Serendipity 2.4.0 and PHP 7.4.33</p>
      # <h1><a href="serendipity_admin.php"><span class="visuallyhidden">Serendipity Administration Suite: </span>$sometitle</a></h1>
      #
      if( ">Powered by Serendipity" >< buf ||
          egrep( string:buf, pattern:"<(title|h[0-9]+)>.*Serendipity Administration Suite.*</(title|h[0-9]+)>", icase:FALSE ) ) {

        vers = eregmatch( string:buf, pattern:"Serendipity ([0-9.]+[-a-zA-Z0-9]*)", icase:TRUE );
        if( vers[1] ) {
          version = vers[1];
          concluded = "  " + vers[0];
          if( conclUrl )
            conclUrl += '\n';
          conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    } else {
      version = vers[1];
      concluded = "  " + vers[0];
    }

    set_kb_item( name:"serendipity/detected", value:TRUE );
    set_kb_item( name:"serendipity/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:s9y:serendipity:" );
    if( ! cpe )
      cpe = "cpe:/a:s9y:serendipity";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Serendipity",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded ),
                 port:port );
  }
}

exit( 0 );
