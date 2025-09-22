# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100926");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-12-01 14:30:53 +0100 (Wed, 01 Dec 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pandora FMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Pandora FMS.");

  script_xref(name:"URL", value:"https://pandorafms.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/pandora_console", "/fms", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item: dir + "/index.php", port:port );

  if( res =~ "<title>Pandora( |&#x20;)FMS -" ) {

    version = "unknown";

    # ver_num">v7.0NG.740<
    ver = eregmatch( string:res, pattern:'ver_num">v[0-9.]+NG\\.([0-9]+)<' );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
    } else {
      ver = eregmatch( string:res, pattern:">v([0-9.]+(SP[0-9]+)?( Build [a-zA-Z0-9]+)?)", icase:TRUE );

      if( ! isnull( ver[1] ) )
        version = chomp( ver[1] );
    }

    set_kb_item( name:"pandora_fms/detected", value:TRUE );
    set_kb_item( name:"pandora_fms/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9A-Za-z. ]+)", base:"cpe:/a:artica:pandora_fms:" );
    if( ! cpe )
      cpe = "cpe:/a:artica:pandora_fms";

    cpe = str_replace( string:cpe, find:" ", replace:"_" );

    register_product( cpe:cpe, location:install, port:port , service:"www" );

    log_message( data:build_detection_report( app:"Pandora FMS", version:version, install:install, cpe:cpe,
                                              concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
