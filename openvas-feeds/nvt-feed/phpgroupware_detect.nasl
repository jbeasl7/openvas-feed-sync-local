# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100092");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2009-03-30 14:26:52 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("phpGroupWare Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://phpgroupware.org/");

  script_tag(name:"summary", value:"This host is running phpGroupWare, a web based messaging,
  collaboration and enterprise management platform.");

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

foreach dir( make_list_unique( "/phpgroupware", "/phpgw", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/login.php", port:port );
  if( buf == NULL ) continue;

  if( egrep( pattern:'<meta name="AUTHOR" content="phpGroupWare http://www.phpgroupware.org" />', string:buf ) ||
      egrep( pattern:'powered by phpGroupWare', string:buf ) ||
      egrep( pattern:'http://www.phpgroupware.org"><img src=.*logo.gif" alt="phpGroupWare"', string:buf ) ||
      ( egrep( pattern:">phpGroupWare [0-9.]<", string:buf ) && egrep( pattern:'type="hidden" name="passwd_type"', string:buf ) ) ) {

    if( dir == "" ) rootInstalled = TRUE;
    vers = "unknown";
    version = eregmatch( string:buf, pattern:'<font color="#000000" size="-1">phpGroupWare ([0-9.]+)</font>' );

    if( ! isnull( version[1] ) ) {
      vers = version[1];
    } else {
      version = eregmatch( string:buf, pattern:'<font color="000000" size="-1">([0-9.]+)</font>' );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
      }
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/phpGroupWare", value:tmp_version );
    set_kb_item( name:"phpGroupWare/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:phpgroupware:phpgroupware:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:phpgroupware:phpgroupware';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"phpGroupWare",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

exit( 0 );
