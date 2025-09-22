# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900381");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mahara Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Mahara.");

  script_xref(name:"URL", value:"https://mahara.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/mahara", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( port:port, item: url );

  if( "Welcome to Mahara" >!< res && 'content="Mahara' >!< res ) {
    url = dir + "/admin/index.php";
    res = http_get_cache( item: url, port:port );
  }

  if( "Log in to Mahara" >< res || "Welcome to Mahara" >< res || 'content="Mahara' >< res ) {
    version = "unknown";
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"mahara/detected", value:TRUE );
    set_kb_item( name:"mahara/http/detected", value:TRUE );

    foreach file( make_list( "/Changelog", "/ChangeLog", "/debian/Changelog" ) ) {
      url2 = dir + file;
      res2 = http_get_cache( item: url2, port:port );
      if( "mahara" >< res2 ) {
        # For greping the version lines
        vers = egrep( pattern:"([0-9.]+[0-9.]+[0-9]+ \([0-9]{4}-[0-9]{2}-[0-9]{2}\))", string:res2 );
        # For matching the first occurring version
        vers = eregmatch( pattern:"^(mahara\ )?\(?(([0-9.]+[0-9.]+[0-9]+)(\~" +
                                  "(beta|alpha)([0-9]))?\-?([0-9])?)\)?([^0-9]"+
                                  "|$)", string:vers );
        # For replacing '~' or '-' with '.'
        vers = ereg_replace( pattern:string("[~|-]"), replace:string("."), string:vers[2] );
      }

      if( !isnull( vers ) ) {
        version = vers;
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
        break;
      }
    }

    if( version == "unknown" ) {
      url2 = dir + "/lib/version.php.temp";
      req = http_get( port:port, item:url2 );
      res2 = http_keepalive_send_recv( port:port, data:req );

      # $config->release = '17.04.2testing';
      vers = eregmatch( pattern:"config->release = '([0-9.]+)", string:res2 );
      if( !isnull(vers[1] ) ) {
        version = vers[1];
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      } else {
        # <meta name="generator" content="Mahara 15.10 (https://mahara.org)" />
        vers = eregmatch( pattern:'content="Mahara ([0-9.]+)', string: res);
        if( !isnull( vers[1] ) )
          version = vers[1];
      }
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+\.[0-9.]+)\.?([a-z0-9]+)?", base:"cpe:/a:mahara:mahara:" );
    if( !cpe )
      cpe = "cpe:/a:mahara:mahara";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Mahara", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
