# SPDX-FileCopyrightText: 2009 LSS
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102009");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-09-18 16:06:42 +0200 (Fri, 18 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("WebAPP Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 LSS");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.web-app.org/");

  script_tag(name:"summary", value:"The remote host is running WebAPP, an open source web portal written
  in Perl.");

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

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  ver = "unknown";

  # Grab index
  found = 0;
  res = http_get_cache( item:dir + "/", port:port );

  pat = '<meta name=.Generator. content=.WebAPP[^0-9]*([^>"]*)';
  match = egrep( pattern:pat, string:res, icase:TRUE );

  # If match is found, try to extract the version
  if( match ) {
    item = eregmatch( pattern:pat, string:match, icase:TRUE );
    ver = item[1];
    found = 1;
  }

  # If version is empty, try different approach
  if( ! ver ) {
    pat = 'This site was made with[^>]*>WebAPP([^>]*>)*[^>]*>v([0-9.]*)';
    item = eregmatch( pattern:pat, string:res, icase:TRUE );
    if( item ) {
      ver = item[2];
      found = 1;
    }
  }

  if( found ) {
    tmp_version = ver + " under " + install;
    set_kb_item( name:"www/" + port + "/webapp", value:tmp_version );
    set_kb_item( name:"WebAPP/installed", value:TRUE );

    cpe = build_cpe( value:ver, exp:"^([0-9.]+)", base:"cpe:/a:web_app.net:webapp:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:web_app.net:webapp';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"WebAPP",
                                              version:ver,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                                              port:port );
  }
}

exit( 0 );
