# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140232");
  script_version("2024-06-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-06-13 05:05:46 +0000 (Thu, 13 Jun 2024)");
  script_tag(name:"creation_date", value:"2017-03-31 13:50:07 +0200 (Fri, 31 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC PowerScale OneFS (Isilion OneFS) Detection (NTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ntp_open.nasl");
  script_require_udp_ports("Services/udp/ntp", 123);
  script_mandatory_keys("ntp/system_banner/available");

  script_tag(name:"summary", value:"NTP based detection of Dell EMC PowerScale OneFS (formerly
  Isilion OneFS).");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");

port = service_get_port( default:123, ipproto:"udp", proto:"ntp" );

if( ! os = get_kb_item( "ntp/" + port + "/system_banner" ) )
  exit( 0 );

if( "Isilon OneFS" >< os ) {
  version = "unknown";

  set_kb_item( name:"dell/emc_isilon/onefs/detected", value:TRUE );
  set_kb_item( name:"dell/emc_isilon/onefs/ntp/port", value:port );
  set_kb_item( name:"dell/emc_isilon/onefs/ntp/" + port + "/concluded", value:os );

  vers = eregmatch( pattern:"Isilon OneFS/v([0-9.]+)", string:os );
  if( ! isnull( vers[1] ) )
    version = vers[1];

  set_kb_item( name:"dell/emc_isilon/onefs/ntp/" + port + "/version", value:version );
}

exit( 0 );
