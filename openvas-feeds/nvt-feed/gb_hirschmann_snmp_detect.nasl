# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108313");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-12-11 11:03:31 +0100 (Mon, 11 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Hirschmann Devices Detection (SNMP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"This script performs SNMP based detection of Hirschmann Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("snmp_func.inc");

port    = snmp_get_port( default:161 );
sysdesc = snmp_get_sysdescr( port:port );
if( ! sysdesc || sysdesc !~ "^Hirschmann" ) exit( 0 );

set_kb_item( name:"hirschmann_device/detected", value:TRUE );
set_kb_item( name:"hirschmann_device/snmp/detected", value:TRUE );
set_kb_item( name:"hirschmann_device/snmp/port", value:port );

fw_version    = "unknown";
product_name  = "unknown";
platform_name = "unknown";

# Hirschmann MACH
# Hirschmann BAT-R 9.12.5750 / 20.10.2017 942070999000000110
# Hirschmann EAGLE Security Device
# Hirschmann Modular Industrial Communication Equipment
# Hirschmann Railswitch
prod_name = eregmatch( pattern:'^Hirschmann ([^\n0-9]+)', string:sysdesc );
if( prod_name[1] ) product_name = chomp( prod_name[1] );

# https://github.com/librenms/librenms/blob/master/mibs/hirschmann/hmpriv.mib
# http://www.circitor.fr/Mibs/Html/H/HMPRIV-MGMT-SNMP-MIB.php
oid = snmp_get( port:port, oid:"1.3.6.1.4.1.248.14.1.1.2.0" ); #hmSysVersion, hmPNIOSoftwareRelease seems to be not available on the tested devices

# SW: 5.07 CH: 1.00 BP: 000
# SW: L2P-09.0.04 CH: 1.10 BP: 000
sw_banner = eregmatch( pattern:"^SW: (.*) CH: ", string:oid );

if( sw_banner ) {

  set_kb_item( name:"hirschmann_device/snmp/" + port + "/concluded", value:oid );
  set_kb_item( name:"hirschmann_device/snmp/" + port + "/concludedOID", value:"1.3.6.1.4.1.248.14.1.1.2.0" );

  vers_nd_model = eregmatch( pattern:"([0-9a-zA-Z]+)-([0-9a-zA-Z]+-)?([0-9.]+)", string:sw_banner[1] );

  if( vers_nd_model ) {

    fw_version = vers_nd_model[3];

    if( vers_nd_model[2] ) {
      platform_name  = vers_nd_model[1] + "-";
      platform_name += ereg_replace( pattern:"-$", string:vers_nd_model[2], replace:"" );
    } else {
      platform_name = vers_nd_model[1];
    }
  } else {
    vers = eregmatch( pattern:"([0-9.]+)", string:sw_banner[1] );
    if( vers ) fw_version = vers[1];
  }
} else {
  set_kb_item( name:"hirschmann_device/snmp/" + port + "/concluded", value:sysdesc );
}

set_kb_item( name:"hirschmann_device/snmp/" + port + "/fw_version", value:fw_version );
set_kb_item( name:"hirschmann_device/snmp/" + port + "/product_name", value:product_name );
set_kb_item( name:"hirschmann_device/snmp/" + port + "/platform_name", value:platform_name );

exit( 0 );
