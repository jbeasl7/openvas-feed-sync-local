# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108310");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-12-07 08:03:31 +0100 (Thu, 07 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSAFE Devices Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/netgear/prosafe/detected");

  script_tag(name:"summary", value:"This script performs Telnet based detection of NETGEAR ProSAFE devices.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

port   = telnet_get_port( default:23 );
banner = telnet_get_banner( port:port );
if( ! banner )
  exit( 0 );

# nb: It seems to be possible to change the banner.
# The banner also contains only the model name by default so each model needs to be added here.
# Some of the devices are also restricting the amount of connections with a message
# like "Sorry, maximum number of connections reached!"
if( "User:" >< banner && ( "(GSM7224V2)" >< banner || "(GSM7224)" >< banner ) ) {

  model      = "unknown";
  fw_version = "unknown";
  fw_build   = "unknown";

  mod = eregmatch( pattern:"\(([0-9a-zA-Z\\-]+)\)", string:banner, icase:TRUE );
  if( mod[1] ) {
    model = mod[1];
    set_kb_item( name:"netgear/prosafe/telnet/" + port + "/concluded", value:mod[0] );
  }

  set_kb_item( name:"netgear/prosafe/telnet/" + port + "/model", value:model );
  set_kb_item( name:"netgear/prosafe/telnet/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"netgear/prosafe/telnet/" + port + "/fw_build", value:fw_build );
  set_kb_item( name:"netgear/prosafe/telnet/detected", value:TRUE );
  set_kb_item( name:"netgear/prosafe/telnet/port", value:port );
  set_kb_item( name:"netgear/prosafe/detected", value:TRUE );
}

exit( 0 );
