# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901008");
  script_version("2023-07-12T05:05:05+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:05 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("ELOG Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ELOG_HTTP/banner");
  script_require_ports("Services/www", 8080);

  script_tag(name:"summary", value:"HTTP based detection of ELOG.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://elog.psi.ch/elog/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );
if( banner !~ "Server\s*:\s*ELOG[ -]" )
  exit( 0 );

install = "/";
version = "unknown";

# Server: ELOG HTTP 3.1.4-966
# Server: ELOG HTTP 3.1.4-966e3dd
# Server: ELOG HTTP 2.9.0-2396
# Server: ELOG HTTP 2.6.5-1918
vers = eregmatch( pattern:"Server\s*:\s*ELOG HTTP (([0-9.]+)-?([0-9a-f]+)?)", string:banner, icase:TRUE );
if( ! isnull( vers[1] ) ) {
  version = ereg_replace( pattern:"-$", string:vers[1], replace:"" );
  version = ereg_replace( pattern:"-", string:version, replace:"." );
}

set_kb_item( name:"ELOG/detected", value:TRUE );
set_kb_item( name:"elog/detected", value:TRUE );
set_kb_item( name:"elog/http/detected", value:TRUE );

register_and_report_cpe( app:"ELOG",
                         ver:version,
                         concluded:vers[0],
                         base:"cpe:/a:stefan_ritt:elog_web_logbook:",
                         expr:"^([0-9a-f.]+)",
                         insloc:install,
                         regPort:port,
                         regService:"www" );

exit( 0 );
