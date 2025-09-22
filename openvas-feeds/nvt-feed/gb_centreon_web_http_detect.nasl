# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100427");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-02-04T05:37:53+0000");
  script_tag(name:"last_modification", value:"2025-02-04 05:37:53 +0000 (Tue, 04 Feb 2025)");
  script_tag(name:"creation_date", value:"2010-01-06 10:44:19 +0100 (Wed, 06 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Centreon Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_xref(name:"URL", value:"http://www.centreon.com/");
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

foreach dir( make_list_unique( "/centreon", http_cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );

 if( egrep( pattern:"<title>Centreon - IT & Network Monitoring</title>", string:buf, icase:TRUE ) &&
                    "LoginInvitVersion" >< buf ) {
    vers = "unknown";

    version = eregmatch( string:buf, pattern:'<td class="LoginInvitVersion"><br />[^0-9.]+([0-9.]+)[^<]+</td>',
                         icase:TRUE );
    if( ! version )
      version = eregmatch( string:buf, pattern:'<span>.*v. ([0-9.]+)', icase:FALSE );

    if( ! isnull( version[1] ) )
      vers = version[1];

    set_kb_item( name:"centreon_web/detected", value:TRUE );
    set_kb_item( name:"centreon_web/http/detected", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:centreon:centreon:" );
    if( ! cpe )
      cpe = 'cpe:/a:centreon:centreon';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    # Be wary that this is "Centreon Web", whose version may differ from "Centreon"
    log_message( data:build_detection_report( app:"Centreon Web", version:vers, install:install, cpe:cpe,
                                              concluded:version[0] ),
                 port:port );
    exit( 0 );

  } else {

    url = dir + "/api/latest/platform/versions";
    buf = http_get_cache( item:url, port:port );

    if( egrep( pattern:'"web":\\{"version":', string:buf, icase:TRUE ) ) {
      vers = "unknown";

      version = eregmatch( string:buf, pattern:'"web":\\{"version":"([0-9.]+)"', icase:TRUE );

      if( ! isnull( version[1] ) )
        vers = version[1];

      set_kb_item( name:"centreon_web/detected", value:TRUE );
      set_kb_item( name:"centreon_web/http/detected", value:TRUE );

      cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:centreon:centreon:" );
      if ( ! cpe )
        cpe = 'cpe:/a:centreon:centreon';

      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Centreon Web", version:vers, install:install, cpe:cpe,
                                                concluded:version[0] ),
                  port:port );
    exit( 0 );
    }
  }
}

exit( 0 );

