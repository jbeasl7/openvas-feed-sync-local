# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105307");
  script_version("2024-05-01T05:05:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-01 05:05:35 +0000 (Wed, 01 May 2024)");
  script_tag(name:"creation_date", value:"2015-06-24 15:27:54 +0200 (Wed, 24 Jun 2015)");
  script_name("F5 LineRate / LROS Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("expressjs/banner");

  script_tag(name:"summary", value:"HTTP based detection of F5 LineRate and the underlying LineRate
  Operating System (LROS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:8443 );

url = "/login";
buf = http_get_cache( item:url, port:port );

if( "<title>LineRate Login</title>" >< buf && buf =~ "X-Powered-By\s*:\s*Express" ) {

  app_cpe = "cpe:/a:f5:linerate";
  os_cpe  = "cpe:/o:f5:lros";
  version = "unknown";
  install = "/";

  set_kb_item( name:"f5/linerate/detected", value:TRUE );
  set_kb_item( name:"f5/linerate/http/detected", value:TRUE );

  register_product( cpe:app_cpe, location:install, port:port, service:"www" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );

  os_register_and_report( os:"F5 LineRate Operating System (LROS)", cpe:os_cpe, port:port,
                          banner_type:"F5 LineRate Login Page", runs_key:"unixoide",
                          desc:"F5 LineRate / LROS Detection (HTTP)" );

  # nb: Seems to be based on FreeBSD according to https://my.f5.com/manage/s/article/K16495 so this
  # is getting registered here as well.
  os_register_and_report( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", port:port,
                          banner_type:"F5 LineRate Login Page", runs_key:"unixoide",
                          desc:"F5 LineRate / LROS Detection (HTTP)" );

  log_message( data:build_detection_report( app:"F5 LineRate",
                                            version:version,
                                            install:install,
                                            cpe:app_cpe ),
               port:port );
}

exit( 0 );
