# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cisco:unified_computing_system";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105799");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-09-02T05:39:48+0000");
  script_tag(name:"last_modification", value:"2025-09-02 05:39:48 +0000 (Tue, 02 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-07-07 10:40:45 +0200 (Thu, 07 Jul 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco UCS Platform Emulator Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_ucs_manager_http_detect.nasl");
  script_mandatory_keys("cisco/ucs_manager/http/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"HTTP based detection of Cisco UCS Platform Emulator.");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = "/";

res = http_get_cache( port:port, item:url );

if( "<title>Cisco UCS Manager</title>" >!< res || "Cisco UCS Platform Emulator" >!< res )
  exit( 0 );

vers = "unknown";
location = "/";
conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"cisco/ucs_platform_emulator/detected", value:TRUE );
set_kb_item( name:"cisco/ucs_platform_emulator/http/detected", value:TRUE );

# >Cisco UCS Platform Emulator 4.2(2aS9PE1) <
vers = eregmatch( pattern:"Cisco UCS Platform Emulator ([0-9.]+\([^\)]+\))", string:res );
if( ! isnull(vers[1] ) )
  version = vers[1];

cpe = build_cpe( value:version, exp:"^([0-9]+\.[0-9A-Za-z().]+)",
                 base:"cpe:/a:cisco:unified_computing_system_platform_emulator:" );
if( ! cpe )
  cpe = "cpe:/a:cisco:unified_computing_system_platform_emulator";

os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, runs_key:"unixoide",
                        desc:"Cisco UCS Platform Emulator Detection (HTTP)" );

register_product( cpe:cpe, location:location, port:port, service:"www" );

log_message( data:build_detection_report( app:"Cisco UCS Platform Emulator", version:version, install: location,
                                          cpe:cpe, concluded:vers[0], concludedUrl:conclUrl ),
             port:port);

exit(0);
