# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108337");
  script_version("2024-08-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-08-13 05:05:46 +0000 (Tue, 13 Aug 2024)");
  script_tag(name:"creation_date", value:"2018-02-15 11:09:51 +0100 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Brocade Fabric OS Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"The script sends an SNMP request to the device and attempts
  to detect the presence of devices running Fabric OS and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default:161 );

# nb: The sysDescr only contains the device name running Fabric OS so don't rely on this
# e.g. Fibre Channel Switch or Connectrix ED-DCX-4S-B
if( ! sysdesc = snmp_get_sysdescr( port:port ) )
  exit( 0 );

# nb: This is actually a different OS from ExtremeNetworks
if( sysdesc =~ "SLX Operating System" )
  exit( 0 );
# swFirmwareVersion
fw_oid = "1.3.6.1.4.1.1588.2.1.1.1.1.6.0";
fw_res = snmp_get( port:port, oid:fw_oid );
# nb: There is no other OID available which would allow to make a more precise detection
# e.g. v3.2.1 or v7.2.1d
if( fw_res =~ "^v([0-9a-z._]+)$" ) {

  version = "unknown";
  set_kb_item( name:"brocade_fabricos/detected", value:TRUE );
  set_kb_item( name:"brocade_fabricos/snmp/detected", value:TRUE );
  set_kb_item( name:"brocade_fabricos/snmp/port", value:port );

  vers = eregmatch( pattern:"^v([0-9a-z._]+)", string:fw_res );
  if( vers[1] ) {
    version = vers[1];
    set_kb_item( name:"brocade_fabricos/snmp/" + port + "/version", value:version );
    set_kb_item( name:"brocade_fabricos/snmp/" + port + "/concluded", value:fw_res );
    set_kb_item( name:"brocade_fabricos/snmp/" + port + "/concludedOID", value:fw_oid );
  }
}

# SilkWorm200E
# Brocade300
# IBM_2005_B16
model_oid = "1.3.6.1.2.1.47.1.1.1.1.2.1";
model_res = snmp_get( port:port, oid:model_oid );

if( model_res ) {
  set_kb_item( name:"brocade_fabricos/snmp/" + port + "/model", value:model_res );
  set_kb_item( name:"brocade_fabricos/snmp/" + port + "/model_oid", value:model_oid );
}

exit( 0 );
