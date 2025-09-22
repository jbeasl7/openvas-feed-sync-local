# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100889");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-16T05:38:45+0000");
  script_tag(name:"last_modification", value:"2025-09-16 05:38:45 +0000 (Tue, 16 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-11-03 12:47:25 +0100 (Wed, 03 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FreePBX Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of FreePBX.");

  script_xref(name:"URL", value:"https://www.freepbx.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) )
  exit (0 );

foreach dir( make_list_unique( "/", "/freepbx", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/admin/config.php";

  res = http_get_cache( port:port, item:url );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  if( "<title>FreePBX" >< res &&
      ( '<div id="version"><a href="http://www.freepbx.org" target="_blank">FreePBX' >< res ||
        'title="FreePBX"' >< res ) ) {
    version = "unknown";
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( string:res, pattern:"FreePBX</a> ([0-9.]+) on <a", icase:TRUE );
    if( ! isnull( vers[1] ) )
       version = chomp( vers[1] );
    else
      vers = eregmatch( string:res, pattern:"freepbx_version=([0-9.]+)", icase:TRUE );

    if( ! isnull( vers[1] ) )
      version = chomp( vers[1] );
    else
      vers = eregmatch( string:res, pattern:"FreePBX ([0-9.]+) is licensed", icase:TRUE );

    if( ! isnull( vers[1] ) )
      version = chomp( vers[1] );
    else
      vers = eregmatch( string:res, pattern:"load_version=([0-9.]+)");

    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item(name:"freepbx/detected", value:TRUE );
    set_kb_item(name:"freepbx/http/detected", value:TRUE );

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:freepbx:freepbx:");
    if( ! cpe )
      cpe = "cpe:/a:freepbx:freepbx";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                            desc:"FreePBX Detection (HTTP)" );

    log_message( data:build_detection_report( app:"FreePBX", version:version, install:install, cpe:cpe,
                                              concluded: vers[0], concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
