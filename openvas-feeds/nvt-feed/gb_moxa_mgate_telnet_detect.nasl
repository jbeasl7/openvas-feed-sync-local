# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105822");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2025-01-17T05:37:18+0000");
  script_tag(name:"last_modification", value:"2025-01-17 05:37:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-07-25 13:26:43 +0200 (Mon, 25 Jul 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa MGate Detection (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/moxa/mgate/detected");

  script_tag(name:"summary", value:"Telnet based detection of Moxa MGate.");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("telnet_func.inc");

port = telnet_get_port( default:23 );

banner = telnet_get_banner( port:port );
banner = bin2string( ddata:banner, noprint_replacement: " ");
if( ! banner || banner !~ "Model name\s*:\s*MGate " )
  exit( 0 );

version = "unknown";
build = "unknown";
model = "unknown";

vb = eregmatch( pattern:'Firmware version\\s*:\\s*([0-9.]+) Build ([0-9]+[^ \r\n])', string:banner );
if( ! isnull( vb[1] ) )
  version = vb[1];

if( ! isnull( vb[2] ) )
  build = vb[2];

mod = eregmatch( pattern:'Model name\\s*:\\s*MGate ([^ \r\n]+)', string:banner );
if( ! isnull( mod[1] ) )
  model = mod[1];

set_kb_item( name:"moxa/mgate/detected", value:TRUE );
set_kb_item( name:"moxa/mgate/telnet/port", value:port );
set_kb_item( name:"moxa/mgate/telnet/" + port + "/concluded", value:banner );
set_kb_item( name:"moxa/mgate/telnet/" + port + "/model", value:model );
set_kb_item( name:"moxa/mgate/telnet/" + port + "/version", value:version );
set_kb_item( name:"moxa/mgate/telnet/" + port + "/build", value:build );

exit(0);
