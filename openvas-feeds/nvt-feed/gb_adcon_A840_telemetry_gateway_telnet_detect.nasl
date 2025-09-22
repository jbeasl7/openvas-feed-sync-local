# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105488");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-03-04T05:38:25+0000");
  script_tag(name:"last_modification", value:"2025-03-04 05:38:25 +0000 (Tue, 04 Mar 2025)");
  script_tag(name:"creation_date", value:"2015-12-17 16:01:19 +0100 (Thu, 17 Dec 2015)");
  script_name("Adcon A840 Telemetry Gateway Detection (Telnet)");

  script_tag(name:"summary", value:"Telnet based detection of a Adcon A840 Telemetry Gateway.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/adcon/telemetry_gateway_a840/detected");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );

banner = telnet_get_banner( port:port );
if( ! banner || "Telemetry Gateway A840" >!< banner )
  exit( 0 );

set_kb_item( name:"adcon/telemetry_gateway_a840/detected", value:TRUE );
set_kb_item( name:"tg_A840/telnet/port", value:port );

version = eregmatch( pattern:'Telemetry Gateway A840 Version ([0-9.]+[^\r\n ]+)', string:banner );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  set_kb_item( name:"tg_A840/telnet/version", value:vers );
}

report = "Detected Adcon Telemetry Gateway A840.";
if( vers )
  report += '\nVersion: ' + vers;

log_message( port:port, data:report );

exit( 0 );
