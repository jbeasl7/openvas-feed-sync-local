# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113223");
  script_version("2023-08-10T05:05:53+0000");
  script_tag(name:"last_modification", value:"2023-08-10 05:05:53 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-07-06 10:41:45 +0200 (Fri, 06 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ecessa ShieldLink Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  script_tag(name:"summary", value:"Checks if the target is an Ecessa ShieldLink
  or PowerLink device, and, if so, retrieves the version using SNMP.");

  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/");
  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/product_comp_shieldlink/");

  exit(0);
}

include( "host_details.inc" );
include( "snmp_func.inc" );

port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if( ! sysdesc ) exit( 0 );

if( sysdesc =~ '^ShieldLink' ) {
  kb_base = 'ecessa_shieldlink';
}
else if ( sysdesc =~ '^PowerLink' ) {
  kb_base = 'ecessa_powerlink';
}
else {
  exit( 0 );
}

set_kb_item( name: "ecessa_link/detected", value: TRUE );
set_kb_item( name: kb_base + "/detected", value: TRUE );
set_kb_item( name: kb_base + "/snmp/port", value: port );
set_kb_item( name: kb_base + "/snmp/concluded", value: sysdesc );

version = "unknown";

vers = eregmatch( string: sysdesc, pattern: 'Link ([0-9.]+) Ecessa' );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
}

set_kb_item( name: kb_base + "/snmp/version", value: version );

exit( 0 );
