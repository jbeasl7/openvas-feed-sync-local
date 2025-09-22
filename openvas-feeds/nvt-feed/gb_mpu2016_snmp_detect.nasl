# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108088");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2014-01-27 18:43:12 +0100 (Mon, 27 Jan 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Emerson Network Power Avocent MergePoint Unity 2016 KVM Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"The script attempts to extract the version number from a previous gathered
  system description from SNMP.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port(default:161);
sysdesc = snmp_get_sysdescr(port:port);
if(!sysdesc) exit(0);

if( sysdesc !~ '^MPU2016 [0-9.]+$' ) exit( 0 );

vers = "unknown";
install = port + "/udp";

version = eregmatch( pattern:'^MPU2016 ([0-9.]+)$', string:sysdesc );
if( ! isnull( version[1] ) ) vers = version[1];

set_kb_item( name:"MPU2016/installed", value:TRUE );

cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware:" );
if( isnull( cpe ) )
  cpe = "cpe:/h:emerson:network_power_avocent_mergepoint_unity_2016_firmware";

register_product( cpe:cpe, location:install, port:port, proto:"udp", service:"snmp" );

log_message( data:build_detection_report( app:"Emerson Network Power Avocent MergePoint Unity 2016 KVM",
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:sysdesc ),
                                          proto:"udp",
                                          port:port );

exit( 0 );
