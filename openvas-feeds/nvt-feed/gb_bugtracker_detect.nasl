# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801278");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BugTracker.NET Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of BugTracker.NET on remote host
  and sets the KB.");

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
if( ! http_can_host_asp( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/btnet", "/bugtracker", "/bugtrackernet", "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item: dir + "/about.html", port:port );
  res2 = http_get_cache( item: dir + "/default.aspx", port:port );

  if( ( res =~ "^HTTP/1\.[01] 200" && ">BugTracker.NET<" >< res ) ||
      ( res2 =~ "^HTTP/1\.[01] 200" && ">BugTracker.NET<" >< res &&
        '"Logon"' >< res2 && ">User:<" >< res2 && ">Password:<" >< res2 ) ) {

    version = "unknown";

    ver = eregmatch( pattern:'Version ([0-9.]+)', string:res );
    if( ! isnull( ver[1] ) ) version = ver[1];

    ## BugTracker.NET 3.4.4 showing its version as 3.4.3
    tmp_version = version +" under "+ install;
    set_kb_item( name:"www/" + port + "/btnet", value:tmp_version );
    set_kb_item( name:"BugTrackerNET/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ifdefined:bugtracker.net:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:ifdefined:bugtracker.net';

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"BugTracker.NET",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
