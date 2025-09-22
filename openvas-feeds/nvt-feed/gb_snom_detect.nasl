# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105168");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-14 11:10:30 +0100 (Wed, 14 Jan 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Snom Detection (SIP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  script_tag(name:"summary", value:"The script attempts to identify a Snom device via a SIP banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

banner = sip_get_banner( port:port, proto:proto );
if( ! banner || "snom" >!< banner )
  exit( 0 );

set_kb_item(name: "snom/detected", value: TRUE);
set_kb_item(name: "snom/sip/port", value: port);
set_kb_item(name: "snom/sip/" + port + "/proto", value: proto);
set_kb_item(name: "snom/sip/" + port + "/" + proto + "/concluded", value: banner);

model_version = eregmatch( pattern:'snom([0-9]*)/([^\r\n]+)', string:banner );

if( ! isnull( model_version[1] ) && model_version[1] != "" )
  set_kb_item( name:"snom/sip/" + port + "/model", value:model_version[1] );

if( ! isnull( model_version[2] ) )
  set_kb_item( name:"snom/sip/" + port + "/version", value:model_version[2] );

exit( 0 );
