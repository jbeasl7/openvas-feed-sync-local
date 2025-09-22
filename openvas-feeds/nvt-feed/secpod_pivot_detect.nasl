# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900578");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pivot Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.pivotlog.net");

  script_tag(name:"summary", value:"This script detects the installed version of Pivot.");

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

foreach dir( make_list_unique( "/pivot", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/pivot/index.php", port:port );

  # nb: Don't use only '<title>Pivot' to avoid false positives against Pivot3 which is a completely different product.
  # The login title was tested against the range of versions in the comment below so this is save to use.
  if( res =~ "^HTTP/1\.[01] 200" && ( "<title>Pivot &#187; Login</title>" >< res || '<a href="http://www.pivotlog.net' >< res ) ) {

    version     = "unknown";
    cpe_version = "unknown";

    # title="Pivot - 1.40.8: 'Dreadwind'"
    # title="Pivot - 1.30 beta 3: 'Rippersnapper'"
    # title="Pivot - 1.30 beta 1a: 'Rippersnapper'"
    # title="Pivot - 1.0: 'Grimlock'"
    vers = eregmatch( pattern:'title="Pivot - ([^:]+)', string:res );
    if( vers[1] ) {
      version     = vers[1];
      cpe_version = ereg_replace( pattern:"(alpha|beta|RC) ", replace:"\1.", string:vers[1] );
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Pivot", value:tmp_version );
    set_kb_item( name:"Pivot/detected", value:TRUE );

    cpe = build_cpe( value:cpe_version, exp:"^([0-9.]+) ?((alpha|beta|RC)( |\.)?([0-9a-z.]+)?)?", base:"cpe:/a:pivot:pivot:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:pivot:pivot";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Pivot",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );
