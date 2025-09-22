# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111080");
  script_version("2024-03-12T05:06:30+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-12 05:06:30 +0000 (Tue, 12 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-02-01 11:00:00 +0100 (Mon, 01 Feb 2016)");
  script_name("Tinyproxy Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Tinyproxy.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "proxy_use.nasl", "global_settings.nasl");
  script_require_ports("Services/http_proxy", 3128, 8888, "Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://tinyproxy.github.io/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

ports = make_list();
proxy_ports = service_get_ports( default_port_list:make_list( 3128, 8888 ), proto:"http_proxy" );
if( proxy_ports )
  ports = make_list( ports, proxy_ports );

www_ports = http_get_ports( default_port_list:make_list( 8080 ) );
if( www_ports )
  ports = make_list( ports, www_ports );

foreach port( ports ) {

  req = http_get( item:"http://www.$$$$$", port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( ! res )
    continue;

  if( banner = egrep( pattern:"^[Ss]erver\s*:\s*tinyproxy", string:res, icase:FALSE ) ) {

    concl = chomp( banner );
    version = "unknown";
    install = port + "/tcp";

    # Server: tinyproxy/1.8.2
    # Server: tinyproxy/1.6.3
    # Server: tinyproxy/1.11.0-rc1-46-git-d3d8943
    ver = eregmatch( pattern:"^[Ss]erver\s*:\s*tinyproxy/([0-9.]+)", string:banner, icase:FALSE );
    if( ver[1] )
      version = ver[1];

    set_kb_item( name:"tinyproxy/detected", value:TRUE );
    set_kb_item( name:"tinyproxy/http/detected", value:TRUE );

    # Tinyproxy is only running on Unix-like OS variants according to: https://tinyproxy.github.io/
    os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:"Tinyproxy banner", port:port, banner:concl, desc:"Tinyproxy Detection (HTTP)", runs_key:"unixoide" );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:banu:tinyproxy:" );
    if( ! cpe )
       cpe = "cpe:/a:banu:tinyproxy";

    register_product( cpe:cpe, location:install, port:port, service:"http_proxy" );

    log_message( data:build_detection_report( app:"Tinyproxy",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concl ),
                 port:port );
  }
}

exit( 0 );
