# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105855");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-02-27T08:17:42+0000");
  script_tag(name:"last_modification", value:"2025-02-27 08:17:42 +0000 (Thu, 27 Feb 2025)");
  script_tag(name:"creation_date", value:"2016-08-08 18:28:02 +0200 (Mon, 08 Aug 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NUUO Device Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of NUUO devices.");

  script_xref(name:"URL", value:"https://nuuo.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

url = "/";

res = http_get_cache( port:port, item:url );

if( res !~ "<title>(NUUO )?Network Video Recorder Login</title>" && 'var VENDOR_NAME "NUUO"' >!< res )
  exit( 0 );

version = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"nuuo/device/detected", value:TRUE );
set_kb_item( name:"nuuo/device/http/detected", value:TRUE );

# href="./css/main.css?v=03.09.0001.0002"
vers = eregmatch( pattern:"\.js\?v=([0-9.]+)", string:res );
if( ! isnull( vers[1] ) ) {
  split_vers = split( vers[1], sep:".", keep:TRUE );
  foreach v ( split_vers ) {
    v = ereg_replace( string:v, pattern:"^0+([0-9]+)", replace:"\1" );
    _vers += v;
  }

  if( _vers )
    version = _vers;
}

if( version == "unknown" ) {
  url = "/upgrade_handle.php?cmd=getcurrentinfo";

  req = http_get (port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req );

  vers = eregmatch( pattern:"<Titan>([0-9.]+)", string:res );
  if( ! isnull( version[1] ) ) {
    split_vers = split( version[1], sep:".", keep:TRUE );
    foreach v ( split_vers ) {
      v = ereg_replace( string:v, pattern:"^0+([0-9]+)", replace:"\1" );
      _vers += v;
    }

    if( _vers ) {
      version = _vers;
      conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                        desc:"NUUO Device Detection (HTTP)" );

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:nuuo:nuuo:" );
if( ! cpe )
  cpe = "cpe:/a:nuuo:nuuo";

register_product( cpe:cpe, location:location, port:port, service:"www" );

log_message( data:build_detection_report( app:"NUUO Network Video Recorder", version:version,
                                          install:location, cpe:cpe, concluded:vers[0],
                                          concludedUrl:conclUrl ),
             port:port );

exit( 0 );
