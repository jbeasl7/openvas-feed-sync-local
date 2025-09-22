# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111100");
  script_version("2025-01-31T15:39:24+0000");
  script_tag(name:"last_modification", value:"2025-01-31 15:39:24 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-05-07 16:00:00 +0200 (Sat, 07 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NodeBB Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of NodeBB.");

  script_add_preference(name:"Master token", value:"", type:"password", id:1);

  script_xref(name:"URL", value:"https://nodebb.org/");
  script_xref(name:"URL", value:"https://docs.nodebb.org/api/read/#section/Overview/Authentication");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("misc_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", "/forum", "/forums", "/community", "/nodebb", "/NodeBB", "/board", "/boards", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = install;
  res = http_get_cache( item:url, port:port );

  # nb: Some have e.g. the following:
  # X-Powered-By: NodeBB
  # which could be included here as a "fallback" as well. Take care to not detect the product on the
  # "wrong" location in this case.
  if( "Not Found</strong>" >!< res &&
      ( concl = eregmatch( string:res, pattern:"(/nodebb\.min\.js|require\(['forum/footer']\);)", icase:FALSE ) )
    ) {
    concluded = "  " + concl[0];
    version = "unknown";

    concludedurl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # e.g.:
    #
    # '{"relative_path":"","version":"1.4.3"
    # var config = JSON.parse('{"relative_path":"","socketioTransports":["polling","websocket"],"websocketAddress":"","version":"0.6.0","siteTitle":"
    # var config = JSON.parse('{"relative_path":"","version":"1.0.0","siteTitle":"
    #
    # nb: Starting with recent versions, there is a version entry but for the fontawesome, which we
    # want to exclude:
    #
    # "fontawesome":{"pro":false,"styles":["solid","brands","regular"],"version":"6.5.2"}
    #
    ver = eregmatch( pattern:'("fontawesome":\\{[^}]+)?"version"\\s*:\\s*"([0-9.]+)"', string:res );
    if( isnull( ver[1] ) && ! isnull( ver[2] ) ) {
      version = ver[2];
      concluded += '\n  ' + ver[0];
    }

    if ( version == "unknown" ) {
      token = script_get_preference( "Master token", id:1 );
      if( ! token ) {
        extra = "Providing a 'Master token' (see referenced URL) to the preferences of the VT 'NodeBB Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.111100) might allow to gather the version from the API.";
      } else {
        url = "/api/admin/dashboard";
        add_headers = make_array( "Authorization", "Bearer " + token );
        req = http_get_req( port:port, url:url, add_headers:add_headers, accept_header:"*/*" );
        res = http_keepalive_send_recv( port:port, data:req );

        if( res !~ "^HTTP/1\.[01] 200" || '{"version":"' >!< res ) {
          if( ! res )
            res = "No response";
          extra = 'Master token provided but login to the API failed with the following response:\n\n' + res;
        }

        # {"version":"1.19.7",
        vers = eregmatch( string:res, pattern:'\\{"version"\\s*:\\s*"([0-9.]+)"' );
        if( vers[1] ) {
          version = vers[1];
          concluded += '\n  ' + vers[0];
          concludedurl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    set_kb_item( name:"nodebb/detected",value:TRUE );
    set_kb_item( name:"nodebb/http/detected",value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nodebb:nodebb:" );
    if( ! cpe )
      cpe = "cpe:/a:nodebb:nodebb";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"NodeBB",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concluded,
                                              concludedUrl:concludedurl,
                                              extra:extra ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
