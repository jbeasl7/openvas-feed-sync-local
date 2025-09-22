# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113070");
  script_version("2025-02-19T05:37:55+0000");
  script_tag(name:"last_modification", value:"2025-02-19 05:37:55 +0000 (Wed, 19 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-12-14 13:17:18 +0100 (Thu, 14 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MikroTik RouterOS Detection (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/mikrotik/routeros/detected");

  script_tag(name:"summary", value:"Telnet based detection of MikroTik RouterOS.");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );

banner = telnet_get_banner( port:port );
if( "MikroTik" >!< banner || "Login:" >!< banner )
  exit( 0 );

version = "unknown";

set_kb_item( name:"mikrotik/routeros/detected", value:TRUE );
set_kb_item( name:"mikrotik/routeros/telnet/detected", value:TRUE );
set_kb_item( name:"mikrotik/routeros/telnet/port", value:port );
set_kb_item( name:"mikrotik/routeros/telnet/" + port + "/concluded", value:banner );

# MikroTik v6.34.6 (bugfix)
# Login:
vers = eregmatch( pattern:"MikroTik v([A-Za-z0-9.]+)", string:banner );
if( ! isnull( vers[1] ) )
  version = vers[1];

set_kb_item( name:"mikrotik/routeros/telnet/" + port + "/version", value:version );

exit( 0 );
