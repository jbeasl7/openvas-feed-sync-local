# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801575");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Hastymail2 Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Hastymail2.");

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

foreach dir( make_list_unique( "/", "/Hastymail2", "/hastymail2", "/hastymail","/hm2", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res = http_get_cache( item: dir + "/index.php", port:port );

  if( "Login | Hastymail2<" >< res && ( "Hastymail Development Group" >< res || "hastymail.ico" >< res ) ) {

    version = "unknown";

    url = dir + "/UPGRADING";
    req = http_get( port:port, item:url );
    res = http_keepalive_send_recv( port:port, data:req );

    # FROM 1.0 to 1.01
    # FROM RC9 to 1.0
    vers = eregmatch( pattern:"to (([a-zA-z]+)?([0-9.]+)( (RC[0-9]))?)", string:res );

    if( ! isnull( vers[1] ) && ! isnull( vers[2] ) )
      version = vers[1];
    else if( !isnull( vers[3] ) && isnull( vers[2] ) )
      version = vers[3];

    if( "RC" >< vers[5] )
      version = version + vers[5];

    if( version != "unknown" )
      concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"hastymail2/detected", value:TRUE );
    set_kb_item( name:"hastymail2/http/detected", value:TRUE );

    cpe = build_cpe( value:tolower( version ), exp:"^([a-z0-9.]+)(rc[0-9]+)?", base:"cpe:/a:hastymail:hastymail2:" );
    if( ! cpe )
      cpe = "cpe:/a:hastymail:hastymail2";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Hastymail2", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl:concUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
