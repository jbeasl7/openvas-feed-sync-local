# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108750");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-17 07:43:42 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Detection (Telnet)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/draytek/detected");

  script_tag(name:"summary", value:"Telnet based detection of DrayTek Vigor devices.");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );

if( ! banner || "Draytek login:" >!< banner )
  exit( 0 );

version = "unknown";

set_kb_item( name:"draytek/vigor/detected", value:TRUE );
set_kb_item( name:"draytek/vigor/telnet/detected", value:TRUE );
set_kb_item( name:"draytek/vigor/telnet/port", value:port );
set_kb_item( name:"draytek/vigor/telnet/" + port + "/concluded", value:chomp( banner ) );
set_kb_item( name:"draytek/vigor/telnet/" + port + "/version", value:version );

exit( 0 );
